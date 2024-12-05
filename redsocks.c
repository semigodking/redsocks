/* redsocks2 - transparent TCP/UDP-to-proxy redirector
 * Copyright (C) 2013-2017 Zhuofei Wang <semigodking@gmail.com>
 *
 * This code is based on redsocks project developed by Leonid Evdokimov.
 * Licensed under the Apache License, Version 2.0 (the "License").
 *
 *
 * Copyright (C) 2007-2011 Leonid Evdokimov <leon@darkk.net.ru>
 *
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include "list.h"
#include "parser.h"
#include "log.h"
#include "main.h"
#include "base.h"
#include "redsocks.h"
#include "utils.h"
#include "tls.h"
#include "http_parser.h"
 
#define MINIMUM_HOST_READ (10)
#define MAXIMUM_HOST_READ (0)

struct http_parser_data {
    const char *last_header_field;
    const char *http_host;
    size_t http_host_length;
};

typedef enum _redsocks_hostname_read_rc {
    SUCCESS = 0,
    DATA_MISSING = 1,
    FATAL_ERROR = 2,
} redsocks_hostname_read_rc;

#define REDSOCKS_RELAY_HALFBUFF 1024*16
#define REDSOCKS_AUDIT_INTERVAL 60*2
static void redsocks_relay_relayreadcb(struct bufferevent *from, void *_client);
static void redsocks_relay_relaywritecb(struct bufferevent *from, void *_client);
void redsocks_event_error(struct bufferevent *buffev, short what, void *_arg);

extern relay_subsys direct_connect_subsys;
extern relay_subsys http_connect_subsys;
#if defined(ENABLE_HTTPS_PROXY)
extern relay_subsys https_connect_subsys;
#endif
extern relay_subsys http_relay_subsys;
extern relay_subsys socks4_subsys;
extern relay_subsys socks5_subsys;
#if !defined(DISABLE_SHADOWSOCKS)
extern relay_subsys shadowsocks_subsys;
#endif
static relay_subsys *relay_subsystems[] =
{
    &direct_connect_subsys,
    &http_connect_subsys,
    &http_relay_subsys,
    &socks4_subsys,
    &socks5_subsys,
#if !defined(DISABLE_SHADOWSOCKS)
    &shadowsocks_subsys,
#endif
#if defined(ENABLE_HTTPS_PROXY)
    &https_connect_subsys,
#endif
};
extern relay_subsys autoproxy_subsys;

static list_head instances = LIST_HEAD_INIT(instances);

static parser_entry redsocks_entries[] =
{
    { .key = "bind",       .type = pt_pchar },
    { .key = "interface",  .type = pt_pchar },
    { .key = "relay",      .type = pt_pchar },
    { .key = "type",       .type = pt_pchar },
    { .key = "login",      .type = pt_pchar },
    { .key = "password",   .type = pt_pchar },
    { .key = "listenq",    .type = pt_uint16 },
 	{ .key = "parse_sni_host", .type = pt_bool },
 	{ .key = "parse_http_host", .type = pt_bool },
    { .key = "min_accept_backoff", .type = pt_uint16 },
    { .key = "max_accept_backoff", .type = pt_uint16 },
    { .key = "autoproxy",  .type = pt_uint16 },
    { .key = "timeout",    .type = pt_uint16 },
    { }
};

/* There is no way to get `EVLIST_INSERTED` event flag outside of libevent, so
 * here are tracking functions. */
static void tracked_event_set(
        struct tracked_event *tev, evutil_socket_t fd, short events,
        void (*callback)(evutil_socket_t, short, void *), void *arg)
{
    tev->ev = event_new(get_event_base(), fd, events, callback, arg);
    timerclear(&tev->inserted);
}

static int tracked_event_add(struct tracked_event *tev, const struct timeval *tv)
{
    int ret = event_add(tev->ev, tv);
    if (ret == 0)
        gettimeofday(&tev->inserted, NULL);
    return ret;
}

static int tracked_event_del(struct tracked_event *tev)
{
    int ret = -1;
    if (tev->ev) {
        ret = event_del(tev->ev);
        if (ret == 0) {
            timerclear(&tev->inserted);
        }
    }
    return ret;
}

static void tracked_event_free(struct tracked_event *tev)
{
    if (tev->ev) {
        if (timerisset(&tev->inserted)) {
            event_del(tev->ev);
            timerclear(&tev->inserted);
        }
        event_free(tev->ev);
        tev->ev = NULL;
    }
}

static int redsocks_onenter(parser_section *section)
{
    // FIXME: find proper way to calulate instance_payload_len
    int instance_payload_len = 0;
    relay_subsys **ss;
    FOREACH(ss, relay_subsystems)
        if (instance_payload_len < (*ss)->instance_payload_len)
            instance_payload_len = (*ss)->instance_payload_len;

    redsocks_instance *instance = calloc(1, sizeof(*instance) + instance_payload_len);
    if (!instance) {
        parser_error(section->context, "Not enough memory");
        return -1;
    }

    INIT_LIST_HEAD(&instance->list);
    INIT_LIST_HEAD(&instance->clients);
    struct sockaddr_in * addr = (struct sockaddr_in *)&instance->config.bindaddr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    /* Default value can be checked in run-time, but I doubt anyone needs that.
     * Linux:   sysctl net.core.somaxconn
     * FreeBSD: sysctl kern.ipc.somaxconn */
    instance->config.listenq = SOMAXCONN;
    instance->config.min_backoff_ms = 100;
    instance->config.max_backoff_ms = 60000;
    instance->config.autoproxy = 0;
    instance->config.timeout =  0;

    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr =
            (strcmp(entry->key, "interface") == 0)  ? (void*)&instance->config.interface :
            (strcmp(entry->key, "bind") == 0)       ? (void*)&instance->config.bind :
            (strcmp(entry->key, "relay") == 0)      ? (void*)&instance->config.relay :
            (strcmp(entry->key, "type") == 0)       ? (void*)&instance->config.type :
            (strcmp(entry->key, "login") == 0)      ? (void*)&instance->config.login :
            (strcmp(entry->key, "password") == 0)   ? (void*)&instance->config.password :
            (strcmp(entry->key, "listenq") == 0)    ? (void*)&instance->config.listenq :
			(strcmp(entry->key, "parse_sni_host") == 0) ? (void*)&instance->config.parse_sni_host :
			(strcmp(entry->key, "parse_http_host") == 0) ? (void*)&instance->config.parse_http_host :
            (strcmp(entry->key, "min_accept_backoff") == 0) ? (void*)&instance->config.min_backoff_ms :
            (strcmp(entry->key, "max_accept_backoff") == 0) ? (void*)&instance->config.max_backoff_ms :
            (strcmp(entry->key, "autoproxy") == 0) ? (void*)&instance->config.autoproxy :
            (strcmp(entry->key, "timeout") == 0) ? (void*)&instance->config.timeout:
            NULL;
    section->data = instance;
    return 0;
}

static int redsocks_onexit(parser_section *section)
{
    /* FIXME: Rewrite in bullet-proof style. There are memory leaks if config
     *        file is not correct, so correct on-the-fly config reloading is
     *        currently impossible.
     */
    const char *err = NULL;
    redsocks_instance *instance = section->data;

    section->data = NULL;
    for (parser_entry *entry = &section->entries[0]; entry->key; entry++)
        entry->addr = NULL;

    // Parse and update bind address and relay address
    if (instance->config.bind) {
        struct sockaddr * addr = (struct sockaddr *)&instance->config.bindaddr;
        int addr_size = sizeof(instance->config.bindaddr);
        if (evutil_parse_sockaddr_port(instance->config.bind, addr, &addr_size))
            err = "invalid bind address";
    }
    if (!err && instance->config.relay) {
        struct sockaddr * addr = (struct sockaddr *)&instance->config.relayaddr;
        int addr_size = sizeof(instance->config.relayaddr);
        if (evutil_parse_sockaddr_port(instance->config.relay, addr, &addr_size)) {
            char * pos = strchr(instance->config.relay, ':');
            char * host = NULL;
            if (pos != NULL)
                host = strndup(instance->config.relay, pos - instance->config.relay);
            else
                host = instance->config.relay;
            int result = resolve_hostname(host, AF_INET, addr);
            if (result != 0) {
                result = resolve_hostname(host, AF_INET6, addr);
            }
            if (result != 0) {
                err = "invalid relay address";
            }
            if (!err && pos != NULL) {
                if (addr->sa_family == AF_INET)
                    ((struct sockaddr_in*)addr)->sin_port = htons(atoi(pos+1));
                else
                    ((struct sockaddr_in6*)addr)->sin6_port = htons(atoi(pos+1));
            }
            if (host != instance->config.relay)
                free(host);
        }
    }

    if (!err && instance->config.type) {
        relay_subsys **ss;
        FOREACH(ss, relay_subsystems) {
            if (!strcmp((*ss)->name, instance->config.type)) {
                instance->relay_ss = *ss;
                list_add(&instance->list, &instances);
                break;
            }
        }
        if (!instance->relay_ss)
            err = "invalid `type` for redsocks";
    }
    else if (!err) {
        err = "no `type` for redsocks";
    }

    if (!err && !instance->config.min_backoff_ms) {
        err = "`min_accept_backoff` must be positive, 0 ms is too low";
    }

    if (!err && !instance->config.max_backoff_ms) {
        err = "`max_accept_backoff` must be positive, 0 ms is too low";
    }

    if (!err && !(instance->config.min_backoff_ms < instance->config.max_backoff_ms)) {
        err = "`min_accept_backoff` must be less than `max_accept_backoff`";
    }

    if (err)
        parser_error(section->context, "%s", err);

    if (instance->config.timeout == 0)
        instance->config.timeout = DEFAULT_CONNECT_TIMEOUT;
    return err ? -1 : 0;
}

static parser_section redsocks_conf_section =
{
    .name    = "redsocks",
    .entries = redsocks_entries,
    .onenter = redsocks_onenter,
    .onexit  = redsocks_onexit
};

void redsocks_log_write_plain(
        const char *file, int line, const char *func, int do_errno,
        const struct sockaddr_storage *clientaddr,
        const struct sockaddr_storage *destaddr,
        int priority, const char *orig_fmt, ...
) {
    int saved_errno = errno;
    va_list ap;
    char clientaddr_str[RED_INET_ADDRSTRLEN], destaddr_str[RED_INET_ADDRSTRLEN];
    char fmt[MAX_LOG_LENGTH+1];

    if (!log_level_enabled(priority))
        return;

    snprintf(fmt, sizeof(fmt),  "[%s->%s]: %s",
                red_inet_ntop(clientaddr, clientaddr_str, sizeof(clientaddr_str)),
                red_inet_ntop(destaddr, destaddr_str, sizeof(destaddr_str)),
                orig_fmt);

    va_start(ap, orig_fmt);
    errno = saved_errno;
    _log_vwrite(file, line, func, do_errno, priority, &fmt[0], ap);
    va_end(ap);
}

void redsocks_touch_client(redsocks_client *client)
{
    redsocks_time(&client->last_event);
}

static inline const char* bufname(redsocks_client *client, struct bufferevent *buf)
{
    assert(buf == client->client || buf == client->relay);
    return buf == client->client ? "client" : "relay";
}

static void redsocks_relay_readcb(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
    redsocks_log_error(client, LOG_DEBUG, "RCB %s, in: %zu", from == client->client?"client":"relay",
                                            evbuffer_get_length(bufferevent_get_input(from)));

    if (evbuffer_get_length(bufferevent_get_output(to)) < get_write_hwm(to)) {
        if (bufferevent_write_buffer(to, bufferevent_get_input(from)) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
        if (bufferevent_enable(from, EV_READ) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
    }
    else {
        if (bufferevent_disable(from, EV_READ) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_disable");
    }
}

int process_shutdown_on_write_(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
    assert(from == client->client || from == client->relay);
    unsigned short from_evshut = from == client->client ? client->client_evshut : client->relay_evshut;
    unsigned short to_evshut = to == client->client ? client->client_evshut : client->relay_evshut;

    redsocks_log_error(client, LOG_DEBUG, "WCB %s, fs: %u, ts: %u, fin: %zu, fout: %zu, tin: %zu",
                                to == client->client?"client":"relay",
                                from_evshut,
                                to_evshut,
                                evbuffer_get_length(bufferevent_get_input(from)),
                                evbuffer_get_length(bufferevent_get_output(from)),
                                evbuffer_get_length(bufferevent_get_input(to)));

    if ((from_evshut & EV_READ) && !(to_evshut & EV_WRITE)
        &&  evbuffer_get_length(bufferevent_get_input(from)) == 0) {
        redsocks_shutdown(client, to, SHUT_WR, 0);
        return 1;
    }
    return 0;
}

static void redsocks_relay_writecb(redsocks_client *client, struct bufferevent *from, struct bufferevent *to)
{
    assert(from == client->client || from == client->relay);
    unsigned short from_evshut = from == client->client ? client->client_evshut : client->relay_evshut;

    if (process_shutdown_on_write_(client, from, to))
        return;
    if (evbuffer_get_length(bufferevent_get_output(to)) < get_write_hwm(to)) {
        if (bufferevent_write_buffer(to, bufferevent_get_input(from)) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
        if (!(from_evshut & EV_READ) && bufferevent_enable(from, EV_READ) == -1)
            redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
    }
}


static void redsocks_relay_relayreadcb(struct bufferevent *from, void *_client)
{
    redsocks_client *client = _client;
    redsocks_touch_client(client);
    redsocks_relay_readcb(client, client->relay, client->client);
}

static void redsocks_relay_relaywritecb(struct bufferevent *to, void *_client)
{
    redsocks_client *client = _client;
    redsocks_touch_client(client);
    redsocks_relay_writecb(client, client->client, client->relay);
}

static void redsocks_relay_clientreadcb(struct bufferevent *from, void *_client)
{
    redsocks_client *client = _client;
    redsocks_touch_client(client);
    redsocks_relay_readcb(client, client->client, client->relay);
}

static void redsocks_relay_clientwritecb(struct bufferevent *to, void *_client)
{
    redsocks_client *client = _client;
    redsocks_touch_client(client);
    redsocks_relay_writecb(client, client->relay, client->client);
}

int redsocks_start_relay(redsocks_client *client)
{
    int error;
    bufferevent_event_cb event_cb;

    bufferevent_setwatermark(client->client, EV_READ|EV_WRITE, 0, REDSOCKS_RELAY_HALFBUFF);
    bufferevent_setwatermark(client->relay, EV_READ|EV_WRITE, 0, REDSOCKS_RELAY_HALFBUFF);
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    bufferevent_getcb(client->client, NULL, NULL, &event_cb, NULL);
#else
    event_cb = client->client->errorcb;
#endif
    bufferevent_setcb(client->client, redsocks_relay_clientreadcb,
                                     redsocks_relay_clientwritecb,
                                     event_cb,
                                     client);
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    bufferevent_getcb(client->relay, NULL, NULL, &event_cb, NULL);
#else
    event_cb = client->relay->errorcb;
#endif
    bufferevent_setcb(client->relay, redsocks_relay_relayreadcb,
                                     redsocks_relay_relaywritecb,
                                     event_cb,
                                     client);

    error = bufferevent_enable(client->client,
                client->client_evshut == EV_READ ? EV_WRITE :
                client->client_evshut == EV_WRITE ? EV_READ :
                client->client_evshut == (EV_READ|EV_WRITE) ? 0 : EV_READ | EV_WRITE);
    if (!error)
        error = bufferevent_enable(client->relay, EV_READ | EV_WRITE);

    if (!error) {
        redsocks_log_error(client, LOG_DEBUG, "data relaying started");
    }
    else {
        redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        redsocks_drop_client(client);
    }
    return error;
}

void redsocks_drop_client(redsocks_client *client)
{
    int fd;
    redsocks_log_error(client, LOG_DEBUG, "dropping client @ state: %d", client->state);

    if (client->instance->config.autoproxy && autoproxy_subsys.fini)
        autoproxy_subsys.fini(client);

    if (client->instance->relay_ss->fini)
        client->instance->relay_ss->fini(client);

    if (client->client) {
        fd = bufferevent_getfd(client->client);
        bufferevent_disable(client->client, EV_READ|EV_WRITE);
        bufferevent_free(client->client);
        redsocks_close(fd);
    }

    if (client->relay) {
        fd = bufferevent_getfd(client->relay);
        bufferevent_disable(client->relay, EV_READ|EV_WRITE);
        bufferevent_free(client->relay);
        redsocks_close(fd);
    }

    list_del(&client->list);
    if (client->hostname != NULL)
        free(client->hostname);
    free(client);
}

void redsocks_shutdown(redsocks_client *client, struct bufferevent *buffev, int how, int pseudo)
{
    short evhow = 0;
    char *strev, *strhow = NULL, *strevhow = NULL;
    unsigned short *pevshut;

    assert(how == SHUT_RD || how == SHUT_WR || how == SHUT_RDWR);
    assert(buffev == client->client || buffev == client->relay);

    if (how == SHUT_RD) {
        strhow = "SHUT_RD";
        evhow = EV_READ;
        strevhow = "EV_READ";
    }
    else if (how == SHUT_WR) {
        strhow = "SHUT_WR";
        evhow = EV_WRITE;
        strevhow = "EV_WRITE";
    }
    else if (how == SHUT_RDWR) {
        strhow = "SHUT_RDWR";
        evhow = EV_READ|EV_WRITE;
        strevhow = "EV_READ|EV_WRITE";
    }

    assert(strhow && strevhow);

    strev = buffev == client->client ? "client" : "relay";
    pevshut = buffev == client->client ? &client->client_evshut : &client->relay_evshut;

    if (bufferevent_disable(buffev, evhow) != 0)
        redsocks_log_errno(client, LOG_ERR, "bufferevent_disable(%s, %s)", strev, strevhow);

    // if EV_WRITE is already shut and we're going to shutdown read then
    // we're either going to abort data flow (bad behaviour) or confirm EOF
    // and in this case socket is already SHUT_RD'ed
    if (!pseudo)
        if ( !(how == SHUT_RD && (*pevshut & EV_WRITE)) )
            if (shutdown(bufferevent_getfd(buffev), how) != 0) {
                redsocks_log_errno(client, LOG_ERR, "shutdown(%s, %s)", strev, strhow);
                // In case of 'Transport endpoint is not connected', shutdown as SHUT_RDWR.
                if (errno == ENOTCONN)
                    evhow = EV_READ|EV_WRITE;
            }

    *pevshut |= evhow;

    if (client->relay_evshut == (EV_READ|EV_WRITE) && client->client_evshut == (EV_READ|EV_WRITE)) {
        redsocks_log_error(client, LOG_DEBUG, "both client and server disconnected");
        redsocks_drop_client(client);
    }
}

// I assume that -1 is invalid errno value
static int redsocks_socket_geterrno(redsocks_client *client, struct bufferevent *buffev)
{
    int pseudo_errno = red_socket_geterrno(buffev);
    if (pseudo_errno == -1) {
        redsocks_log_errno(client, LOG_ERR, "red_socket_geterrno");
        return -1;
    }
    return pseudo_errno;
}

void redsocks_event_error(struct bufferevent *buffev, short what, void *_arg)
{
    redsocks_client *client = _arg;
    assert(buffev == client->relay || buffev == client->client);

    redsocks_touch_client(client);

    if (!(what & BEV_EVENT_ERROR))
        errno = redsocks_socket_geterrno(client, buffev);
    redsocks_log_errno(client, LOG_DEBUG, "%s, what: " event_fmt_str,
                            buffev == client->client?"client":"relay",
                            event_fmt(what));

    if (what == (BEV_EVENT_READING|BEV_EVENT_EOF)) {
        redsocks_shutdown(client, buffev, SHUT_RD, 1);
        // Ensure the other party could send remaining data and SHUT_WR also
        if (buffev == client->client)
        {
            if (!(client->relay_evshut & EV_WRITE) && client->relay_connected)
                bufferevent_enable(client->relay, EV_WRITE);
        }
        else
        {
            if (!(client->client_evshut & EV_WRITE))
                bufferevent_enable(client->client, EV_WRITE);
        }
    }
    else {
        redsocks_drop_client(client);
    }
}

int sizes_equal(size_t a, size_t b)
{
    return a == b;
}

int sizes_greater_equal(size_t a, size_t b)
{
    return a >= b;
}

int redsocks_read_expected(redsocks_client *client, struct evbuffer *input, void *data, size_comparator comparator, size_t expected)
{
    size_t len = evbuffer_get_length(input);
    if (comparator(len, expected)) {
        int read = evbuffer_remove(input, data, expected);
        UNUSED(read);
        assert(read == expected);
        return 0;
    }
    else {
        redsocks_log_error(client, LOG_NOTICE, "Can't get expected amount of data");
        redsocks_drop_client(client);
        return -1;
    }
}

static int redsocks_http_parser_on_header_field(http_parser *parser, const char *at, size_t length)
{
    struct http_parser_data *parser_data = (struct http_parser_data *) parser->data;

    parser_data->last_header_field = at;

    return 0;
}

static int redsocks_http_parser_on_header_value(http_parser *parser, const char *at, size_t length)
{
    struct http_parser_data *parser_data = (struct http_parser_data *) parser->data;

    if (0 != strncasecmp(parser_data->last_header_field, "host", sizeof("host") - 1)) {
        return 0;
    }

    parser_data->http_host = at;
    parser_data->http_host_length = length;

    http_parser_pause(parser, 1);

    return 0;
}

static int redsocks_peek_buffer(redsocks_client *client, struct bufferevent *buffev, char **peek_buffer, size_t *peek_size)
{
    int n = 0, i = 0;
    char *read_buffer = NULL;
    size_t read_buffer_size = 0;
    size_t read_buffer_position = 0;
    struct evbuffer_iovec *v = NULL;

    n = evbuffer_peek(buffev->input, -1, NULL, NULL, 0);

    v = malloc(sizeof(struct evbuffer_iovec) * n);
    if (NULL == v) {
	redsocks_log_error(client, LOG_ERR, "malloc() error");
        goto finish;
    }

    n = evbuffer_peek(buffev->input, -1, NULL, v, n);

    read_buffer_size = 0;
    for (i = 0; i < n; i++) {
        read_buffer_size +=  v[i].iov_len;
    }

    read_buffer = (char *) malloc(read_buffer_size);
    if (NULL == read_buffer) {
	redsocks_log_error(client, LOG_ERR, "malloc() error");
        goto fail;
    }

    read_buffer_position = 0;
    for (i = 0; i < n; i++) {
        memcpy(&read_buffer[read_buffer_position], v[i].iov_base, v[i].iov_len);
        read_buffer_position += v[i].iov_len;
    }

 fail:
    free(v);

 finish:
    *peek_buffer = read_buffer;
    *peek_size = read_buffer_size;

    return 0;
}

static redsocks_hostname_read_rc redsocks_read_sni(redsocks_client *client, char *read_buffer, size_t read_buffer_size, char **hostname)
{
    int rc = parse_tls_header(read_buffer, read_buffer_size, hostname);

    if (rc >= 0) {
        return SUCCESS;
    }

    /* rc < 0 */

    if (rc != -4) {
        return DATA_MISSING;
    }

    /* rc == -4, malloc failure */
    return FATAL_ERROR;
}

static redsocks_hostname_read_rc redsocks_read_http_host(redsocks_client *client, char *read_buffer, size_t read_buffer_size, char **hostname)
{
    http_parser parser;
    http_parser_settings parser_settings;
    struct http_parser_data parser_data;
    char *temp_hostname = NULL;
    int rc = HPE_UNKNOWN;

    memset(&parser, 0, sizeof(parser));
    memset(&parser_settings, 0, sizeof(parser_settings));
    memset(&parser_data, 0, sizeof(parser_data));

    http_parser_init(&parser, HTTP_REQUEST);

    parser.data = &parser_data;
    parser_settings.on_header_field = redsocks_http_parser_on_header_field;
    parser_settings.on_header_value = redsocks_http_parser_on_header_value;

    rc = http_parser_execute(&parser, &parser_settings, read_buffer, read_buffer_size);

    if (rc != read_buffer_size &&
        HTTP_PARSER_ERRNO(&parser) != HPE_PAUSED) {
        redsocks_log_error(client, LOG_ERR, "error at http parser library: %s",
                           http_errno_description(HTTP_PARSER_ERRNO(&parser)));
        //return FATAL_ERROR;
        return DATA_MISSING; /* Something like "invalid HTTP method" should not be fatal */
    }

    if (rc == read_buffer_size && NULL == parser_data.http_host) {
        return DATA_MISSING;
    }

    if (parser_data.http_host && parser_data.http_host_length) {
        temp_hostname = (char *) malloc(parser_data.http_host_length + 1);
        if (NULL == temp_hostname) {
            return FATAL_ERROR;
        }

        memset(temp_hostname, 0, parser_data.http_host_length + 1);
        memcpy(temp_hostname, parser_data.http_host, parser_data.http_host_length);
        temp_hostname[parser_data.http_host_length] = '\0'; //this should be redundant. (should already be covered by memset)

        /* handle the http://host:port/ situation.
           this is not yet handled by http-parser currently:
           https://github.com/nodejs/http-parser/issues/501 */
        char *colon_ptr = strchr(temp_hostname, ':');
        if (colon_ptr != NULL) memset(colon_ptr, 0, parser_data.http_host_length + 1 - (colon_ptr - temp_hostname));

        *hostname = temp_hostname;

        return SUCCESS;
    }

    /* should be unreachable */
    return FATAL_ERROR;
}

static void redsocks_hostname_reader(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    size_t read_buffer_size = 0;
    char *read_buffer = NULL;
    char *hostname = NULL;
    redsocks_hostname_read_rc rc = FATAL_ERROR;

    assert(client->instance->config.parse_sni_host || client->instance->config.parse_http_host);

    if (!client->instance->config.parse_sni_host && !client->instance->config.parse_http_host) {
        return;
    }

    if (client->relay != NULL) {
        return;
    }

    if (0 != redsocks_peek_buffer(client, buffev, &read_buffer, &read_buffer_size)) {
        redsocks_drop_client(client);
        return;
    }

    if (client->instance->config.parse_sni_host) {
        redsocks_log_error(client, LOG_INFO, "searching for hostname by TLS SNI");
        rc = redsocks_read_sni(client, read_buffer, read_buffer_size, &hostname);
    }
    if (rc != SUCCESS && rc != FATAL_ERROR && client->instance->config.parse_http_host) {
        redsocks_log_error(client, LOG_INFO, "searching for hostname by HTTP Host header");
        rc = redsocks_read_http_host(client, read_buffer, read_buffer_size, &hostname);
    }

    client->hostname = NULL;

    switch (rc) {

    case SUCCESS:
        client->hostname = hostname;
        redsocks_log_error(client, LOG_INFO, "found hostname %s,", client->hostname);
    case DATA_MISSING:
        redsocks_log_error(client, LOG_INFO, "now connecting...");
        if (client->instance->relay_ss->connect_relay) {
            client->instance->relay_ss->connect_relay(client);
        } else {
            redsocks_connect_relay(client);
        }

        break;

    case FATAL_ERROR: /* passthourgh */
    default:
        redsocks_drop_client(client);
    }

    free(read_buffer);
}

struct evbuffer *mkevbuffer(void *data, size_t len)
{
    struct evbuffer *buff = NULL, *retval = NULL;

    buff = evbuffer_new();
    if (!buff) {
        log_errno(LOG_ERR, "evbuffer_new");
        goto fail;
    }

    if (evbuffer_add(buff, data, len) < 0) {
        log_errno(LOG_ERR, "evbuffer_add");
        goto fail;
    }

    retval = buff;
    buff = NULL;

fail:
    if (buff)
        evbuffer_free(buff);
    return retval;
}

int redsocks_write_helper_ex(
    struct bufferevent *buffev, redsocks_client *client,
    redsocks_message_maker mkmessage, int state, size_t wm_low, size_t wm_high)
{
    assert(client);
    return redsocks_write_helper_ex_plain(buffev, client, (redsocks_message_maker_plain)mkmessage,
                                          client, state, wm_low, wm_high);
}

int redsocks_write_helper_ex_plain(
    struct bufferevent *buffev, redsocks_client *client,
    redsocks_message_maker_plain mkmessage, void *p, int state, size_t wm_low, size_t wm_high)
{
    int len;
    struct evbuffer *buff = NULL;
    int drop = 1;

    if (mkmessage) {
        buff = mkmessage(p);
        if (!buff)
            goto fail;

        assert(!client || buffev == client->relay);
        len = bufferevent_write_buffer(buffev, buff);
        if (len < 0) {
            if (client)
                redsocks_log_errno(client, LOG_ERR, "bufferevent_write_buffer");
            else
                log_errno(LOG_ERR, "bufferevent_write_buffer");
            goto fail;
        }
    }

    if (client)
        client->state = state;
    bufferevent_setwatermark(buffev, EV_READ, wm_low, wm_high);
    bufferevent_enable(buffev, EV_READ);
    drop = 0;

fail:
    if (buff)
        evbuffer_free(buff);
    if (drop && client)
        redsocks_drop_client(client);
    return drop ? -1 : 0;
}

int redsocks_write_helper(
    struct bufferevent *buffev, redsocks_client *client,
    redsocks_message_maker mkmessage, int state, size_t wm_only)
{
    assert(client);
    return redsocks_write_helper_ex(buffev, client, mkmessage, state, wm_only, wm_only);
}

void redsocks_relay_connected(struct bufferevent *buffev, void *_arg)
{
    redsocks_client *client = _arg;
    assert(buffev == client->relay);

    redsocks_touch_client(client);

    if (!red_is_socket_connected_ok(buffev)) {
        redsocks_log_errno(client, LOG_NOTICE, "red_is_socket_connected_ok");
        goto fail;
    }
    client->relay_connected = 1;
    /* We do not need to detect timeouts any more.
    The two peers will handle it. */
    bufferevent_set_timeouts(client->relay, NULL, NULL);
    bufferevent_setcb(client->relay, client->instance->relay_ss->readcb,
                                     client->instance->relay_ss->writecb,
                                     redsocks_event_error,
                                     client);
#if LIBEVENT_VERSION_NUMBER >= 0x02010100
    bufferevent_trigger(client->relay, EV_WRITE, 0);
#else
    if (client->instance->relay_ss->writecb)
        client->instance->relay_ss->writecb(client->relay, client);
#endif
    return;

fail:
    redsocks_drop_client(client);
}

int redsocks_connect_relay(redsocks_client *client)
{
    char * interface = client->instance->config.interface;
    struct timeval tv;
    tv.tv_sec = client->instance->config.timeout;
    tv.tv_usec = 0;

    // Allowing binding relay socket to specified IP for outgoing connections
    client->relay = red_connect_relay(interface,
                                      &client->instance->config.relayaddr,
                                      NULL,
                                      redsocks_relay_connected,
                                      redsocks_event_error, client, &tv);
    if (!client->relay) {
        redsocks_log_errno(client, LOG_ERR, "red_connect_relay failed!!!");
        redsocks_drop_client(client);
        return -1;
    }
    return 0;
}

static void redsocks_accept_backoff(int fd, short what, void *_arg)
{
    redsocks_instance *self = _arg;

    /* Isn't it already deleted? EV_PERSIST has nothing common with timeouts in
     * old libevent... On the other hand libevent does not return any error. */
    if (tracked_event_del(&self->accept_backoff) != 0)
        log_errno(LOG_ERR, "event_del");

    if (tracked_event_add(&self->listener, NULL) != 0)
        log_errno(LOG_ERR, "event_add");
}

void redsocks_close_internal(int fd, const char* file, int line, const char *func)
{
    if (close(fd) == 0) {
        redsocks_instance *instance = NULL;
        struct timeval now;
        gettimeofday(&now, NULL);
        list_for_each_entry(instance, &instances, list) {
            if (timerisset(&instance->accept_backoff.inserted)) {
                struct timeval min_accept_backoff = {
                    instance->config.min_backoff_ms / 1000,
                    (instance->config.min_backoff_ms % 1000) * 1000};
                struct timeval time_passed;
                timersub(&now, &instance->accept_backoff.inserted, &time_passed);
                if (timercmp(&min_accept_backoff, &time_passed, <)) {
                    redsocks_accept_backoff(-1, 0, instance);
                    break;
                }
            }
        }
    }
    else {
        const int do_errno = 1;
        _log_write(file, line, func, do_errno, LOG_WARNING, "close");
    }
}

static void redsocks_accept_client(int fd, short what, void *_arg)
{
    redsocks_instance *self = _arg;
    redsocks_client   *client = NULL;
    struct sockaddr_storage clientaddr;
    struct sockaddr_storage myaddr;
    struct sockaddr_storage destaddr;
    socklen_t addrlen = sizeof(clientaddr);
    int client_fd = -1;
    int error;

    // working with client_fd
    client_fd = accept(fd, (struct sockaddr*)&clientaddr, &addrlen);
    if (client_fd == -1) {
        /* Different systems use different `errno` value to signal different
         * `lack of file descriptors` conditions. Here are most of them.  */
        if (errno == ENFILE || errno == EMFILE || errno == ENOBUFS || errno == ENOMEM) {
            self->accept_backoff_ms = (self->accept_backoff_ms << 1) + 1;
            clamp_value(self->accept_backoff_ms, self->config.min_backoff_ms, self->config.max_backoff_ms);
            int delay = (red_randui32() % self->accept_backoff_ms) + 1;
            log_errno(LOG_WARNING, "accept: out of file descriptors, backing off for %u ms", delay);
            struct timeval tvdelay = { delay / 1000, (delay % 1000) * 1000 };
            if (tracked_event_del(&self->listener) != 0)
                log_errno(LOG_ERR, "event_del");
            if (tracked_event_add(&self->accept_backoff, &tvdelay) != 0)
                log_errno(LOG_ERR, "event_add");
        }
        else {
            log_errno(LOG_WARNING, "accept");
        }
        goto fail;
    }
    self->accept_backoff_ms = 0;

    // socket is really bound now (it could be bound to 0.0.0.0)
    addrlen = sizeof(myaddr);
    error = getsockname(client_fd, (struct sockaddr*)&myaddr, &addrlen);
    if (error) {
        log_errno(LOG_WARNING, "getsockname");
        goto fail;
    }

    error = getdestaddr(client_fd, &clientaddr, &myaddr, &destaddr);
    if (error) {
        goto fail;
    }

    error = evutil_make_socket_nonblocking(client_fd);
    if (error) {
        log_errno(LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

    if (apply_tcp_keepalive(client_fd))
        goto fail;

    // everything seems to be ok, let's allocate some memory
    if (self->config.autoproxy)
        client = calloc(1, sizeof(redsocks_client) +
                            self->relay_ss->payload_len + autoproxy_subsys.payload_len
                            );
    else
        client = calloc(1, sizeof(redsocks_client) + self->relay_ss->payload_len);
    if (!client) {
        log_errno(LOG_ERR, "calloc");
        goto fail;
    }

    client->instance = self;
    memcpy(&client->clientaddr, &clientaddr, sizeof(clientaddr));
    memcpy(&client->destaddr, &destaddr, sizeof(destaddr));
    INIT_LIST_HEAD(&client->list);
    self->relay_ss->init(client);
    if (self->config.autoproxy)
        autoproxy_subsys.init(client);

    if (redsocks_time(&client->first_event) == ((time_t)-1))
        goto fail;

    redsocks_touch_client(client);

    client->client = bufferevent_socket_new(get_event_base(), client_fd, 0);
    if (!client->client) {
        log_errno(LOG_ERR, "bufferevent_socket_new");
        goto fail;
    }
    if (!self->config.parse_sni_host && !self->config.parse_http_host) {
        bufferevent_setcb(client->client, NULL, NULL, redsocks_event_error, client);
    } else {
        bufferevent_setcb(client->client, redsocks_hostname_reader, NULL, redsocks_event_error, client);
    }

    client_fd = -1;

    // enable reading to handle EOF from client
    if (bufferevent_enable(client->client, EV_READ) != 0) {
        redsocks_log_errno(client, LOG_ERR, "bufferevent_enable");
        goto fail;
    }

    list_add(&client->list, &self->clients);

    redsocks_log_error(client, LOG_DEBUG, "accepted");

    if (self->config.parse_sni_host || self->config.parse_http_host) {
        client->client->wm_read.low = MINIMUM_HOST_READ;
        client->client->wm_read.high = MAXIMUM_HOST_READ;
        /* We wait first for the client to give us the host */
        return;
    }

    if (self->config.autoproxy && autoproxy_subsys.connect_relay)
        autoproxy_subsys.connect_relay(client);
    else if (self->relay_ss->connect_relay)
        self->relay_ss->connect_relay(client);
    else
        redsocks_connect_relay(client);

    return;

fail:
    if (client) {
        redsocks_drop_client(client);
    }
    if (client_fd != -1)
        redsocks_close(client_fd);
}

static const char *redsocks_evshut_str(unsigned short evshut)
{
    return
        evshut == EV_READ ? "SHUT_RD" :
        evshut == EV_WRITE ? "SHUT_WR" :
        evshut == (EV_READ|EV_WRITE) ? "SHUT_RDWR" :
        evshut == 0 ? "" :
        "???";
}

static const char *redsocks_event_str(unsigned short what)
{
    return
        what == EV_READ ? "R/-" :
        what == EV_WRITE ? "-/W" :
        what == (EV_READ|EV_WRITE) ? "R/W" :
        what == 0 ? "-/-" :
        "???";
}

void redsocks_dump_client(redsocks_client * client, int loglevel)
{
    time_t now = redsocks_time(NULL);

    const char *s_client_evshut = redsocks_evshut_str(client->client_evshut);
    const char *s_relay_evshut = redsocks_evshut_str(client->relay_evshut);

    redsocks_log_error(client, loglevel, "client(%i): (%s)%s%s input %zu output %zu, relay(%i): (%s)%s%s input %zu output %zu, age: %li sec, idle: %li sec.",
        client->client ? bufferevent_getfd(client->client) : -1,
            redsocks_event_str(client->client ?  bufferevent_get_enabled(client->client) : 0),
            s_client_evshut[0] ? " " : "", s_client_evshut,
            client->client ? evbuffer_get_length(bufferevent_get_input(client->client)) : 0,
            client->client ? evbuffer_get_length(bufferevent_get_output(client->client)) : 0,
        client->relay ? bufferevent_getfd(client->relay) : -1,
            redsocks_event_str(client->relay ? bufferevent_get_enabled(client->relay) : 0),
            s_relay_evshut[0] ? " " : "", s_relay_evshut,
            client->relay ? evbuffer_get_length(bufferevent_get_input(client->relay)) : 0,
            client->relay ? evbuffer_get_length(bufferevent_get_output(client->relay)) : 0,
            now - client->first_event,
            now - client->last_event);
}

static void redsocks_dump_instance(redsocks_instance *instance)
{
    redsocks_client *client = NULL;
    char addr_str[RED_INET_ADDRSTRLEN];

    log_error(LOG_INFO, "Dumping client list for instance (%s @ %s):",
              instance->relay_ss->name,
              red_inet_ntop(&instance->config.bindaddr, addr_str, sizeof(addr_str)));
    list_for_each_entry(client, &instance->clients, list)
        redsocks_dump_client(client, LOG_INFO);

    log_error(LOG_INFO, "End of client list.");
}

static void redsocks_debug_dump()
{
    redsocks_instance *instance = NULL;

    list_for_each_entry(instance, &instances, list)
        redsocks_dump_instance(instance);
}

/* Audit is required to clean up hung connections.
 * Not all connections are closed gracefully by both ends. In any case that
 * either far end of client or far end of relay does not close connection
 * gracefully, we got hung connections.
 */
static void redsocks_audit_instance(redsocks_instance *instance)
{
    redsocks_client *tmp, *client = NULL;
    time_t now = redsocks_time(NULL);
    int drop_it = 0;
    char addr_str[RED_INET_ADDRSTRLEN];

    log_error(LOG_DEBUG, "Audit client list for instance (%s @ %s):",
              instance->relay_ss->name,
              red_inet_ntop(&instance->config.bindaddr, addr_str, sizeof(addr_str)));
    list_for_each_entry_safe(client, tmp, &instance->clients, list) {
        drop_it = 0;

        if (now - client->last_event >= REDSOCKS_AUDIT_INTERVAL){
            /* Only take actions if no touch of the client for at least an audit cycle.*/
            /* drop this client if either end disconnected */
            if ((client->client_evshut == EV_WRITE && client->relay_evshut == EV_READ)
                || (client->client_evshut == EV_READ && client->relay_evshut == EV_WRITE)
                || (client->client_evshut == (EV_READ|EV_WRITE) && client->relay_evshut == EV_WRITE)
                || (client->client_evshut == EV_READ && client->relay == NULL))
                drop_it = 1;
        }
        /* close long connections without activities */
        if (now - client->last_event >= 3600 * 2)
            drop_it = 1;

        if (drop_it){
            redsocks_dump_client(client, LOG_DEBUG);
            redsocks_drop_client(client);
        }
    }
    log_error(LOG_DEBUG, "End of auditing client list.");
}

static void redsocks_audit(int sig, short what, void *_arg)
{
    redsocks_instance * tmp, *instance = NULL;

    list_for_each_entry_safe(instance, tmp, &instances, list)
        redsocks_audit_instance(instance);
}

static void redsocks_fini_instance(redsocks_instance *instance);

static int redsocks_init_instance(redsocks_instance *instance)
{
    /* FIXME: redsocks_fini_instance is called in case of failure, this
     *        function will remove instance from instances list - result
     *        looks ugly.
     */
    int error;
    int bindaddr_len = 0;
    evutil_socket_t fd = -1;

    if (instance->relay_ss->instance_init
        && instance->relay_ss->instance_init(instance)) {
        log_errno(LOG_ERR, "Failed to init relay subsystem.");
        goto fail;
    }

    fd = socket(instance->config.bindaddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1) {
        log_errno(LOG_ERR, "socket");
        goto fail;
    }

    error = evutil_make_listen_socket_reuseable(fd);
    if (error) {
        log_errno(LOG_ERR, "evutil_make_listen_socket_reuseable");
        goto fail;
    }

    // iptables TPROXY target does not send packets to non-transparent sockets
    if (make_socket_transparent(fd))
        log_error(LOG_WARNING, "Continue without TPROXY support");

    if (apply_reuseport(fd))
        log_error(LOG_WARNING, "Continue without SO_REUSEPORT enabled");

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    bindaddr_len = instance->config.bindaddr.ss_len > 0 ? instance->config.bindaddr.ss_len : sizeof(instance->config.bindaddr);
#else
    bindaddr_len = sizeof(instance->config.bindaddr);
#endif
    error = bind(fd, (struct sockaddr*)&instance->config.bindaddr, bindaddr_len);
    if (error) {
        log_errno(LOG_ERR, "bind");
        goto fail;
    }

    error = evutil_make_socket_nonblocking(fd);
    if (error) {
        log_errno(LOG_ERR, "evutil_make_socket_nonblocking");
        goto fail;
    }

    apply_tcp_fastopen(fd);
    error = listen(fd, instance->config.listenq);
    if (error) {
        log_errno(LOG_ERR, "listen");
        goto fail;
    }

    tracked_event_set(&instance->listener, fd, EV_READ | EV_PERSIST, redsocks_accept_client, instance);
    fd = -1;

    tracked_event_set(&instance->accept_backoff, -1, 0, redsocks_accept_backoff, instance);

    error = tracked_event_add(&instance->listener, NULL);
    if (error) {
        log_errno(LOG_ERR, "event_add");
        goto fail;
    }

    return 0;

fail:
    redsocks_fini_instance(instance);

    if (fd != -1) {
        redsocks_close(fd);
    }

    return -1;
}

/* Drops instance completely, freeing its memory and removing from
 * instances list.
 */
static void redsocks_fini_instance(redsocks_instance *instance) {
    if (!list_empty(&instance->clients)) {
        redsocks_client *tmp, *client = NULL;

        log_error(LOG_WARNING, "There are connected clients during shutdown! Disconnecting them.");
        list_for_each_entry_safe(client, tmp, &instance->clients, list) {
            redsocks_drop_client(client);
        }
    }

    if (instance->relay_ss->instance_fini)
        instance->relay_ss->instance_fini(instance);

    if (instance->listener.ev) {
        int fd = event_get_fd(instance->listener.ev);
        tracked_event_free(&instance->listener);
        redsocks_close(fd);
        memset(&instance->listener, 0, sizeof(instance->listener));
    }
    tracked_event_free(&instance->accept_backoff);
    memset(&instance->accept_backoff, 0, sizeof(instance->accept_backoff));

    list_del(&instance->list);

    free(instance->config.type);
    free(instance->config.login);
    free(instance->config.password);
    free(instance->config.interface);

    memset(instance, 0, sizeof(*instance));
    free(instance);
}

static int redsocks_fini();

static struct event * audit_event = NULL;

static int redsocks_init() {
    redsocks_instance *tmp, *instance = NULL;
    struct timeval audit_time;
    struct event_base * base = get_event_base();

    /* Start audit */
    audit_time.tv_sec = REDSOCKS_AUDIT_INTERVAL;
    audit_time.tv_usec = 0;
    audit_event = event_new(base, -1, EV_TIMEOUT|EV_PERSIST, redsocks_audit, NULL);
    if (!audit_event)
        goto fail;
    if (evtimer_add(audit_event, &audit_time))
        goto fail;

    list_for_each_entry_safe(instance, tmp, &instances, list) {
        if (redsocks_init_instance(instance) != 0)
            goto fail;
    }

    return 0;

fail:
    // that was the first resource allocation, it return's on failure, not goto-fail's
    redsocks_fini();

    return -1;
}

static int redsocks_fini()
{
    redsocks_instance *tmp, *instance = NULL;

    list_for_each_entry_safe(instance, tmp, &instances, list)
        redsocks_fini_instance(instance);

    /* stop audit */
    if (audit_event) {
        evtimer_del(audit_event);
        event_free(audit_event);
        audit_event = NULL;
    }
    return 0;
}

app_subsys redsocks_subsys =
{
    .init = redsocks_init,
    .fini = redsocks_fini,
    .dump = redsocks_debug_dump,
    .conf_section = &redsocks_conf_section,
};



/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
