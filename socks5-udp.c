/* redsocks2 - transparent TCP-to-proxy redirector
 * Copyright (C) 2013-2017 Zhuofei Wang <semigodking@gmail.com>
 *
 * This code is based on redsocks project developed by Leonid Evdokimov.
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include "main.h"
#include "utils.h"
#include "log.h"
#include "redudp.h"
#include "redsocks.h"
#include "socks5.h"

typedef struct socks5_expected_assoc_reply_t {
    socks5_reply h;
    union {
        socks5_addr_ipv4 v4;
        socks5_addr_ipv6 v6;
    };
} PACKED socks5_expected_assoc_reply;

static struct evbuffer* socks5_mkmethods_plain_wrapper(void *p)
{
    int *do_password = p;
    return socks5_mkmethods_plain(*do_password);
}

static struct evbuffer* socks5_mkpassword_plain_wrapper(void *p)
{
    redudp_instance *self = p;
    return socks5_mkpassword_plain(self->config.login, self->config.password);
}

static struct evbuffer* socks5_mkassociate(void *p)
{
    return socks5_mkcommand_plain(socks5_cmd_udp_associate, p);
}

static void socks5_fill_preamble(
       socks5_udp_preamble *preamble,
       struct sockaddr * addr,
       size_t *preamble_len)
{
    preamble->reserved = 0;
    preamble->frag_no = 0; /* fragmentation is not supported */
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in * in_addr = (struct sockaddr_in *) addr;
        preamble->addrtype = socks5_addrtype_ipv4;
        preamble->addr.v4.addr = in_addr->sin_addr.s_addr;
        preamble->addr.v4.port = in_addr->sin_port;
        *preamble_len = 4 + sizeof(preamble->addr.v4);
    }
    else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 * in6_addr = (struct sockaddr_in6 *) addr;
        preamble->addrtype = socks5_addrtype_ipv6;
        memcpy(&preamble->addr.v6, &in6_addr->sin6_addr, sizeof(in6_addr->sin6_addr));
        preamble->addr.v6.port = in6_addr->sin6_port;
        *preamble_len = 4 + sizeof(preamble->addr.v6);
    }
}



/**************************************************************************
 * Logic
 * */

typedef struct socks5_client_t {
    struct event        udprelay;
    struct sockaddr_storage udprelayaddr;
    struct bufferevent *relay;
    int ready_fwd;
} socks5_client;

static void socks5_client_init(redudp_client *client)
{
    socks5_client *socks5client = (void*)(client + 1);
    memset(socks5client, 0, sizeof(socks5_client));
}

static void socks5_client_fini(redudp_client *client)
{
    socks5_client *socks5client = (void*)(client + 1);
    int fd;

    if (event_initialized(&socks5client->udprelay)) {
        fd = event_get_fd(&socks5client->udprelay);
        if (event_del(&socks5client->udprelay) == -1)
            redudp_log_errno(client, LOG_ERR, "event_del");
        close(fd);
    }
    if (socks5client->relay) {
        fd = bufferevent_getfd(socks5client->relay);
        bufferevent_free(socks5client->relay);
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
}

static int socks5_ready_to_fwd(struct redudp_client_t *client)
{
    socks5_client *socks5client = (void*)(client + 1);
    return socks5client->ready_fwd; 
}

static void socks5_forward_pkt(redudp_client *client, struct sockaddr *destaddr, void *buf, size_t pktlen)
{
    socks5_client *socks5client = (void*)(client + 1);
    socks5_udp_preamble req;
    struct msghdr msg;
    struct iovec io[2];
    size_t preamble_len = 0;

    if (socks5client->udprelayaddr.ss_family != AF_INET && socks5client->udprelayaddr.ss_family != AF_INET6) {
        redudp_log_errno(client, LOG_WARNING, "Unknown address type %d",
                         socks5client->udprelayaddr.ss_family);
        return;
    }

    socks5_fill_preamble(&req, destaddr, &preamble_len);
    ssize_t outgoing, fwdlen = pktlen + preamble_len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &socks5client->udprelayaddr;
    msg.msg_namelen = sizeof(socks5client->udprelayaddr);
    msg.msg_iov = io;
    msg.msg_iovlen = SIZEOF_ARRAY(io);

    io[0].iov_base = &req;
    io[0].iov_len = preamble_len;
    io[1].iov_base = buf;
    io[1].iov_len = pktlen;

    outgoing = sendmsg(event_get_fd(&socks5client->udprelay), &msg, 0);
    if (outgoing == -1) {
        redudp_log_errno(client, LOG_WARNING, "sendmsg: Can't forward packet, dropping it");
        return;
    }
    else if (outgoing != fwdlen) {
        redudp_log_error(client, LOG_WARNING, "sendmsg: I was sending %zd bytes, but only %zd were sent.", fwdlen, outgoing);
        return;
    }
}

static void socks5_pkt_from_socks(int fd, short what, void *_arg)
{
    redudp_client *client = _arg;
    socks5_client *socks5client = (void*)(client + 1);
    union {
        char buf[MAX_UDP_PACKET_SIZE];
        socks5_udp_preamble header;
    } * pkt = client->instance->shared_buff;
    ssize_t pktlen, fwdlen;
    struct sockaddr_storage udprelayaddr;

    assert(fd == event_get_fd(&socks5client->udprelay));

    pktlen = red_recv_udp_pkt(fd, pkt->buf, MAX_UDP_PACKET_SIZE, &udprelayaddr, NULL);
    if (pktlen == -1)
        return;

    if (evutil_sockaddr_cmp((struct sockaddr *)&udprelayaddr,
                            (struct sockaddr *)&socks5client->udprelayaddr,
                            1) != 0) {
        char buf[RED_INET_ADDRSTRLEN];
        redudp_log_error(client, LOG_NOTICE, "Got packet from unexpected address %s.",
                         red_inet_ntop(&udprelayaddr, buf, sizeof(buf)));
        return;
    }

    if (pkt->header.frag_no != 0) {
        // FIXME: does anybody need it?
        redudp_log_error(client, LOG_WARNING, "Got fragment #%u. Packet fragmentation is not supported!",
                         pkt->header.frag_no);
        return;
    }

    if (pkt->header.addrtype != socks5_addrtype_ipv4 && pkt->header.addrtype != socks5_addrtype_ipv6) {
        redudp_log_error(client, LOG_NOTICE, "Got address type #%u.", pkt->header.addrtype);
        return;
    }

    // Support IPv6
    struct sockaddr_storage src_addr;
    size_t header_size = 4;
    if (pkt->header.addrtype == socks5_addrtype_ipv4) {
        struct sockaddr_in * src = (struct sockaddr_in *)&src_addr;
        src->sin_family = AF_INET;
        src->sin_addr.s_addr = pkt->header.addr.v4.addr;
        src->sin_port = pkt->header.addr.v4.port;
        header_size += sizeof(socks5_addr_ipv4);
    }
    else if (pkt->header.addrtype == socks5_addrtype_ipv6) {
        struct sockaddr_in6 * src = (struct sockaddr_in6 *)&src_addr;
        src->sin6_family = AF_INET6;
        src->sin6_addr = pkt->header.addr.v6.addr;
        src->sin6_port = pkt->header.addr.v6.port;
        header_size += sizeof(socks5_addr_ipv6);
    }
    // TODO: Support domain addr

    fwdlen = pktlen - header_size;
    redudp_fwd_pkt_to_sender(client, pkt->buf + header_size, fwdlen, &src_addr);
}


static size_t calc_assoc_reply_size(int ss_family) {
    size_t reply_size = sizeof(socks5_reply);
    if (ss_family == AF_INET)
        reply_size += sizeof(socks5_addr_ipv4);
    else if (ss_family == AF_INET6)
        reply_size += sizeof(socks5_addr_ipv6);
    return reply_size;
}

static void socks5_read_assoc_reply(struct bufferevent *buffev, void *_arg)
{
    redudp_client *client = _arg;
    socks5_client *socks5client = (void*)(client + 1);
    struct evbuffer * input = bufferevent_get_input(buffev);
    int fd = -1;
    int error;
    size_t max_reply_size = calc_assoc_reply_size(AF_INET6);

    // Inspect reply code
    {
        socks5_reply * reply = (socks5_reply *)evbuffer_pullup(input, -1);
        size_t data_size = evbuffer_get_length(input);

        if (data_size < sizeof(socks5_reply)) {
            // Wait for more data
            bufferevent_setwatermark(buffev, EV_READ, sizeof(socks5_reply), max_reply_size);
            return;
        }
        if (reply->ver != socks5_ver) {
            redudp_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected reply version: %u", reply->ver);
            goto fail;
        }
        if (reply->status != socks5_status_succeeded) {
            redudp_log_error(client, LOG_NOTICE, "Socks5 server status: \"%s\" (%i)",
                    socks5_status_to_str(reply->status), reply->status);
            goto fail;
        }
        if (reply->addrtype == socks5_addrtype_ipv4)
            max_reply_size = calc_assoc_reply_size(AF_INET);
        else if (reply->addrtype == socks5_addrtype_ipv6)
            max_reply_size = calc_assoc_reply_size(AF_INET6);
        else {
            redudp_log_error(client, LOG_NOTICE, "Socks5 server replies bad address type: %d", reply->addrtype);
            goto fail;
        }

        if (data_size < max_reply_size) {
            // Wait for more data
            bufferevent_setwatermark(buffev, EV_READ, max_reply_size, max_reply_size);
            return;
        }
    }
    // Enough data received
    socks5_expected_assoc_reply reply;
    int read = evbuffer_remove(bufferevent_get_input(buffev), &reply, max_reply_size);
    redudp_log_error(client, LOG_DEBUG, "<trace>");

    if (read != max_reply_size) {
        // Should never occur
        redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %zu",
                         read, max_reply_size);
        goto fail;
    }

    // Use relay address instead of address in reply.
    // Unless server allocates different IP for UDP association,
    // this should work.
    // Use port number from UDP association reply as destination
    // port.
    memcpy(&socks5client->udprelayaddr,
            &client->instance->config.relayaddr,
            sizeof(struct sockaddr_storage));
    if (reply.h.addrtype == socks5_addrtype_ipv4) {
        set_sockaddr_port(&socks5client->udprelayaddr, reply.v4.port);
    }
    else if (reply.h.addrtype == socks5_addrtype_ipv6) {
        set_sockaddr_port(&socks5client->udprelayaddr, reply.v6.port);
    }

    fd = socket(socks5client->udprelayaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == -1) {
        redudp_log_errno(client, LOG_ERR, "socket");
        goto fail;
    }

    error = evutil_make_socket_nonblocking(fd);
    if (error) {
        redudp_log_errno(client, LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    error = connect(fd, (struct sockaddr*)&socks5client->udprelayaddr, sizeof(struct sockaddr_in));
#else
    error = connect(fd, (struct sockaddr*)&socks5client->udprelayaddr, sizeof(socks5client->udprelayaddr));
#endif
    if (error) {
        redudp_log_errno(client, LOG_NOTICE, "connect");
        goto fail;
    }

    event_assign(&socks5client->udprelay, get_event_base(), fd, EV_READ | EV_PERSIST, socks5_pkt_from_socks, client);
    error = event_add(&socks5client->udprelay, NULL);
    if (error) {
        redudp_log_errno(client, LOG_ERR, "event_add");
        goto fail;
    }

    socks5client->ready_fwd = 1;
    redudp_flush_queue(client);
    // TODO: bufferevent_disable ?
    return;

fail:
    if (fd != -1)
        close(fd);
    redudp_drop_client(client);
}

static void socks5_read_auth_reply(struct bufferevent *buffev, void *_arg)
{
    redudp_client *client = _arg;
    socks5_client *socks5client = (void*)(client + 1);
    socks5_auth_reply reply;
    int read = evbuffer_remove(bufferevent_get_input(buffev), &reply, sizeof(reply));
    int error;
    redudp_log_error(client, LOG_DEBUG, "<trace>");

    if (read != sizeof(reply)) {
        redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %zu",
                         read, sizeof(reply));
        goto fail;
    }

    if (reply.ver != socks5_password_ver || reply.status != socks5_password_passed) {
        redudp_log_error(client, LOG_NOTICE, "Socks5 authentication error. Version: %u, error code: %u",
                         reply.ver, reply.status);
        goto fail;
    }

    size_t reply_size = calc_assoc_reply_size(client->instance->config.relayaddr.ss_family);
    error = redsocks_write_helper_ex_plain(
            socks5client->relay, NULL, socks5_mkassociate, &client->destaddr, 0,
            sizeof(socks5_reply), reply_size);
    if (error)
        goto fail;

    replace_readcb(socks5client->relay, socks5_read_assoc_reply);
    return;

fail:
    redudp_drop_client(client);
}


static void socks5_read_auth_methods(struct bufferevent *buffev, void *_arg)
{
    redudp_client *client = _arg;
    socks5_client *socks5client = (void*)(client + 1);
    int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
    socks5_method_reply reply;
    int read = evbuffer_remove(bufferevent_get_input(buffev), &reply, sizeof(reply));
    const char *error = NULL;
    int ierror = 0;
    redudp_log_error(client, LOG_DEBUG, "do_password: %d", do_password);

    if (read != sizeof(reply)) {
        redudp_log_errno(client, LOG_NOTICE, "evbuffer_remove returned only %i bytes instead of expected %zu",
                         read, sizeof(reply));
        goto fail;
    }

    error = socks5_is_known_auth_method(&reply, do_password);
    if (error) {
        redudp_log_error(client, LOG_NOTICE, "socks5_is_known_auth_method: %s", error);
        goto fail;
    }
    else if (reply.method == socks5_auth_none) {
        size_t reply_size = calc_assoc_reply_size(client->instance->config.relayaddr.ss_family);
        ierror = redsocks_write_helper_ex_plain(
                socks5client->relay, NULL, socks5_mkassociate, &client->destaddr, 0,
                sizeof(socks5_reply), reply_size);
        if (ierror)
            goto fail;
        replace_readcb(socks5client->relay, socks5_read_assoc_reply);
    }
    else if (reply.method == socks5_auth_password) {
        ierror = redsocks_write_helper_ex_plain(
                socks5client->relay, NULL, socks5_mkpassword_plain_wrapper, client->instance, 0, /* last one is ignored */
                sizeof(socks5_auth_reply), sizeof(socks5_auth_reply));
        if (ierror)
            goto fail;
        replace_readcb(socks5client->relay, socks5_read_auth_reply);
    }

    return;

fail:
    redudp_drop_client(client);
}

static void socks5_relay_connected(struct bufferevent *buffev, void *_arg)
{
    redudp_client *client = _arg;
    socks5_client *socks5client = (void*)(client + 1);
    int do_password = socks5_is_valid_cred(client->instance->config.login, client->instance->config.password);
    int error;
    char relayaddr_str[RED_INET_ADDRSTRLEN];
    redudp_log_error(client, LOG_DEBUG, "via %s", red_inet_ntop(&client->instance->config.relayaddr, relayaddr_str, sizeof(relayaddr_str)));

    if (!red_is_socket_connected_ok(buffev)) {
        redudp_log_errno(client, LOG_NOTICE, "red_is_socket_connected_ok");
        goto fail;
    }

    error = redsocks_write_helper_ex_plain(
            socks5client->relay, NULL, socks5_mkmethods_plain_wrapper, &do_password, 0 /* does not matter */,
            sizeof(socks5_method_reply), sizeof(socks5_method_reply));
    if (error)
        goto fail;

    replace_readcb(socks5client->relay, socks5_read_auth_methods);
    replace_writecb(socks5client->relay, NULL);
    //bufferevent_disable(buffev, EV_WRITE); // I don't want to check for writeability.
    return;

fail:
    redudp_drop_client(client);
}

static void socks5_relay_error(struct bufferevent *buffev, short what, void *_arg)
{
    redudp_client *client = _arg;
    // TODO: FIXME: Implement me
    redudp_log_error(client, LOG_NOTICE, "socks5_relay_error");
    redudp_drop_client(client);
}


static void socks5_connect_relay(redudp_client *client)
{
    socks5_client *socks5client = (void*)(client + 1);
    socks5client->relay = red_connect_relay(
            NULL,
            &client->instance->config.relayaddr,
            NULL,
            socks5_relay_connected,
            socks5_relay_error,
            client,
            NULL);
    if (!socks5client->relay)
        redudp_drop_client(client);
}

static int socks5_instance_init(struct redudp_instance_t *instance)
{
    return 0;
}

static void socks5_instance_fini(struct redudp_instance_t *instance)
{
}

udprelay_subsys socks5_udp_subsys =
{
    .name                 = "socks5",
    .payload_len          = sizeof(socks5_client),
    .instance_payload_len = 0,
    .init                 = socks5_client_init,
    .fini                 = socks5_client_fini,
    .instance_init          = socks5_instance_init,
    .instance_fini          = socks5_instance_fini,
    .connect_relay          = socks5_connect_relay,
    .forward_pkt          = socks5_forward_pkt,
    .ready_to_fwd          = socks5_ready_to_fwd,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
