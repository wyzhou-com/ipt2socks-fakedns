#define _GNU_SOURCE
#include "tcp_proxy.h"
#include "ctx.h"
#include "netutils.h"
#include "socks5.h"
#include "fakedns.h"
#include "logutils.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <arpa/inet.h>

/* splice() api */
#ifndef SPLICE_F_MOVE
  #include <sys/syscall.h>

  #undef  SPLICE_F_MOVE
  #define SPLICE_F_MOVE 1

  #undef  SPLICE_F_NONBLOCK
  #define SPLICE_F_NONBLOCK 2

  #define splice(fdin, offin, fdout, offout, len, flags) syscall(__NR_splice, fdin, offin, fdout, offout, len, flags)
#endif

/* Forward declarations */
static void tcp_socks5_connect_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void tcp_stream_payload_forward_cb(evloop_t *evloop, evio_t *watcher, int revents);


static inline tcp_context_t* get_tcpctx_by_watcher(evio_t *watcher) {
    if (watcher->events & EV_CUSTOM) {
        return (void *)watcher - offsetof(tcp_context_t, client_watcher);
    } else {
        return (void *)watcher - offsetof(tcp_context_t, socks5_watcher);
    }
}

static inline void tcp_context_release(evloop_t *evloop, tcp_context_t *context, bool is_tcp_reset) {
    evio_t *client_watcher = &context->client_watcher;
    evio_t *socks5_watcher = &context->socks5_watcher;
    ev_io_stop(evloop, client_watcher);
    ev_io_stop(evloop, socks5_watcher);
    if (is_tcp_reset) {
        tcp_close_by_rst(client_watcher->fd);
        tcp_close_by_rst(socks5_watcher->fd);
    } else {
        close(client_watcher->fd);
        close(socks5_watcher->fd);
    }
    if (client_watcher->data || socks5_watcher->data) {
        free(client_watcher->data);
        free(socks5_watcher->data);
    } else {
        close(context->client_pipefd[0]);
        close(context->client_pipefd[1]);
        close(context->socks5_pipefd[0]);
        close(context->socks5_pipefd[1]);
    }
    free(context);
}

void tcp_tproxy_accept_cb(evloop_t *evloop, evio_t *accept_watcher, int revents __attribute__((unused))) {
    bool isipv4 = accept_watcher->data;
    skaddr6_t skaddr; char ipstr[IP6STRLEN]; portno_t portno;

    int client_sockfd = tcp_accept(accept_watcher->fd, (void *)&skaddr, &(socklen_t){sizeof(skaddr)});
    if (client_sockfd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[tcp_tproxy_accept_cb] accept tcp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[tcp_tproxy_accept_cb] source socket address: %s#%hu", ipstr, portno);
    }

    if (!get_tcp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, client_sockfd, &skaddr, !(g_options & OPT_TCP_USE_REDIRECT))) {
        tcp_close_by_rst(client_sockfd);
        return;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[tcp_tproxy_accept_cb] target socket address: %s#%hu", ipstr, portno);
    }

    int socks5_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);
    const void *tfo_data = (g_options & OPT_ENABLE_TFO_CONNECT) ? &g_socks5_auth_request : NULL;
    uint16_t tfo_datalen = (g_options & OPT_ENABLE_TFO_CONNECT) ? sizeof(socks5_authreq_t) : 0;
    ssize_t tfo_nsend = -1; /* if tfo connect succeed: tfo_nsend >= 0 */

    if (!tcp_connect(socks5_sockfd, &g_server_skaddr, tfo_data, tfo_datalen, &tfo_nsend)) {
        LOGERR("[tcp_tproxy_accept_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        tcp_close_by_rst(client_sockfd);
        close(socks5_sockfd);
        return;
    }
    if (tfo_nsend >= 0) {
        LOGINF("[tcp_tproxy_accept_cb] tfo send to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, tfo_nsend);
    } else {
        LOGINF("[tcp_tproxy_accept_cb] try to connect to %s#%hu ...", g_server_ipstr, g_server_portno);
    }

    tcp_context_t *context = malloc(sizeof(*context));

    /* if (watcher->events & EV_CUSTOM); then it is client watcher; fi */
    evio_t *watcher = &context->client_watcher;
    ev_io_init(watcher, tcp_stream_payload_forward_cb, client_sockfd, EV_READ | EV_CUSTOM);

    /* build the ipv4/ipv6 proxy request (send to the socks5 proxy server) */
    const char *fake_domain = NULL;
    char domain_buf[256];
    if ((g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        if (fakedns_reverse_lookup(((skaddr4_t *)&skaddr)->sin_addr.s_addr, domain_buf, sizeof(domain_buf))) {
            fake_domain = domain_buf;
            LOGINF("[tcp_tproxy_accept_cb] fakedns hit: %u.%u.%u.%u -> %s", 
                ((uint8_t *)&skaddr)[4], ((uint8_t *)&skaddr)[5], ((uint8_t *)&skaddr)[6], ((uint8_t *)&skaddr)[7], fake_domain);
        }
    }
    
    size_t reqlen_est = (fake_domain) ? (sizeof(socks5_domainreq_t) + strlen(fake_domain) + 2) : 
                        (isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t));
    
    context->client_watcher.data = malloc(reqlen_est);
    
    size_t actual_len = 0;
    socks5_proxy_request_make(context->client_watcher.data, &skaddr, fake_domain, &actual_len);
    context->client_length = actual_len;

    watcher = &context->socks5_watcher;
    if (tfo_nsend >= 0 && (size_t)tfo_nsend >= tfo_datalen) {
        ev_io_init(watcher, tcp_socks5_recv_authresp_cb, socks5_sockfd, EV_READ);
        tfo_nsend = 0; /* reset to zero for next send */
    } else {
        ev_io_init(watcher, tfo_nsend >= 0 ? tcp_socks5_send_authreq_cb : tcp_socks5_connect_cb, socks5_sockfd, EV_WRITE);
        tfo_nsend = tfo_nsend >= 0 ? tfo_nsend : 0;
    }
    ev_io_start(evloop, watcher);

    context->socks5_watcher.data = malloc(sizeof(socks5_ipv6resp_t));
    context->socks5_length = (size_t)tfo_nsend;
}

static void tcp_socks5_connect_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_has_error(socks5_watcher->fd)) {
        LOGERR("[tcp_socks5_connect_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    LOGINF("[tcp_socks5_connect_cb] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);
    ev_set_cb(socks5_watcher, tcp_socks5_send_authreq_cb);
    ev_invoke(evloop, socks5_watcher, EV_WRITE);
}

/* return: -1(error_occurred); 0(partial_sent); 1(completely_sent) */
static int tcp_socks5_send_request(const char *funcname, evloop_t *evloop, evio_t *socks5_watcher, const void *data, size_t datalen) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    ssize_t nsend = send(socks5_watcher->fd, data + context->socks5_length, datalen - context->socks5_length, 0);
    if (nsend < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] send to %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            tcp_context_release(evloop, context, true);
            return -1;
        }
        return 0;
    }
    LOGINF("[%s] send to %s#%hu, nsend:%zd", funcname, g_server_ipstr, g_server_portno, nsend);
    context->socks5_length += (size_t)nsend;
    if (context->socks5_length >= datalen) {
        context->socks5_length = 0;
        return 1;
    }
    return 0;
}

/* return: -1(error_occurred); 0(partial_recv); 1(completely_recv) */
static int tcp_socks5_recv_response(const char *funcname, evloop_t *evloop, evio_t *socks5_watcher, void *data, size_t datalen) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    ssize_t nrecv = recv(socks5_watcher->fd, data + context->socks5_length, datalen - context->socks5_length, 0);
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] recv from %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            tcp_context_release(evloop, context, true);
            return -1;
        }
        return 0;
    }
    if (nrecv == 0) {
        LOGERR("[%s] recv from %s#%hu: connection is closed", funcname, g_server_ipstr, g_server_portno);
        tcp_context_release(evloop, context, true);
        return -1;
    }
    LOGINF("[%s] recv from %s#%hu, nrecv:%zd", funcname, g_server_ipstr, g_server_portno, nrecv);
    context->socks5_length += (size_t)nrecv;
    if (context->socks5_length >= datalen) {
        context->socks5_length = 0;
        return 1;
    }
    return 0;
}

static void tcp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_send_request("tcp_socks5_send_authreq_cb", evloop, socks5_watcher, &g_socks5_auth_request, sizeof(socks5_authreq_t)) != 1) {
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_recv_authresp_cb, socks5_watcher->fd, EV_READ);
    ev_io_start(evloop, socks5_watcher);
}

static void tcp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_recv_response("tcp_socks5_recv_authresp_cb", evloop, socks5_watcher, socks5_watcher->data, sizeof(socks5_authresp_t)) != 1) {
        return;
    }
    if (!socks5_auth_response_check("tcp_socks5_recv_authresp_cb", socks5_watcher->data)) {
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    const void *data = g_socks5_usrpwd_requestlen ? &g_socks5_usrpwd_request : context->client_watcher.data;
    uint16_t datalen = g_socks5_usrpwd_requestlen ? g_socks5_usrpwd_requestlen : context->client_length;
    int ret = tcp_socks5_send_request("tcp_socks5_recv_authresp_cb", evloop, socks5_watcher, data, datalen);
    if (ret == 1) {
        ev_set_cb(socks5_watcher, g_socks5_usrpwd_requestlen ? tcp_socks5_recv_usrpwdresp_cb : tcp_socks5_recv_proxyresp_cb);
        if (!g_socks5_usrpwd_requestlen) context->client_length = 5; // response_length (header prefix)
    } else if (ret == 0) {
        ev_io_stop(evloop, socks5_watcher);
        ev_io_init(socks5_watcher, g_socks5_usrpwd_requestlen ? tcp_socks5_send_usrpwdreq_cb : tcp_socks5_send_proxyreq_cb, socks5_watcher->fd, EV_WRITE);
        ev_io_start(evloop, socks5_watcher);
    }
}

static void tcp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_send_request("tcp_socks5_send_usrpwdreq_cb", evloop, socks5_watcher, &g_socks5_usrpwd_request, g_socks5_usrpwd_requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_recv_usrpwdresp_cb, socks5_watcher->fd, EV_READ);
    ev_io_start(evloop, socks5_watcher);
}

static void tcp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    if (tcp_socks5_recv_response("tcp_socks5_recv_usrpwdresp_cb", evloop, socks5_watcher, socks5_watcher->data, sizeof(socks5_usrpwdresp_t)) != 1) {
        return;
    }
    if (!socks5_usrpwd_response_check("tcp_socks5_recv_usrpwdresp_cb", socks5_watcher->data)) {
        tcp_context_release(evloop, get_tcpctx_by_watcher(socks5_watcher), true);
        return;
    }
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    int ret = tcp_socks5_send_request("tcp_socks5_recv_usrpwdresp_cb", evloop, socks5_watcher, context->client_watcher.data, context->client_length);
    if (ret == 1) {
        ev_set_cb(socks5_watcher, tcp_socks5_recv_proxyresp_cb);
        context->client_length = 5; // response_length (header prefix)
    } else if (ret == 0) {
        ev_io_stop(evloop, socks5_watcher);
        ev_io_init(socks5_watcher, tcp_socks5_send_proxyreq_cb, socks5_watcher->fd, EV_WRITE);
        ev_io_start(evloop, socks5_watcher);
    }
}

static void tcp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (tcp_socks5_send_request("tcp_socks5_send_proxyreq_cb", evloop, socks5_watcher, context->client_watcher.data, context->client_length) != 1) {
        return;
    }
    ev_io_stop(evloop, socks5_watcher);
    ev_io_init(socks5_watcher, tcp_socks5_recv_proxyresp_cb, socks5_watcher->fd, EV_READ);
    ev_io_start(evloop, socks5_watcher);
    context->client_length = 5; // Read first 5 bytes (VER, REP, RSV, ATYP, LEN/IP1)
}

static void tcp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *socks5_watcher, int revents __attribute__((unused))) {
    tcp_context_t *context = get_tcpctx_by_watcher(socks5_watcher);
    if (tcp_socks5_recv_response("tcp_socks5_recv_proxyresp_cb", evloop, socks5_watcher, socks5_watcher->data, context->client_length) != 1) {
        return;
    }
    
    /* If we just read the first 5 bytes (Header prefix) */
    if (context->client_length == 5) {
        uint8_t atype = ((socks5_ipv4resp_t *)socks5_watcher->data)->addrtype;
        size_t total_len;
        
        if (atype == SOCKS5_ADDRTYPE_IPV4) {
            total_len = sizeof(socks5_ipv4resp_t); // 10
        } else if (atype == SOCKS5_ADDRTYPE_IPV6) {
            total_len = sizeof(socks5_ipv6resp_t); // 22
        } else if (atype == SOCKS5_ADDRTYPE_DOMAIN) {
            uint8_t domain_len = ((socks5_domainresp_t *)socks5_watcher->data)->domain_len;
            total_len = sizeof(socks5_domainresp_t) + domain_len + 2;
        } else {
             LOGERR("[tcp_socks5_recv_proxyresp_cb] unsupported address type: 0x%02x", atype);
             tcp_context_release(evloop, context, true);
             return;
        }
        
        /* Expand buffer if needed */
        if (total_len > 5) {
            void *new_buf = realloc(socks5_watcher->data, total_len);
            if (!new_buf) {
                LOGERR("[tcp_socks5_recv_proxyresp_cb] realloc failed");
                tcp_context_release(evloop, context, true);
                return;
            }
            socks5_watcher->data = new_buf;
            
            /* Update length targets */
            context->client_length = total_len;
            context->socks5_length = 5; /* We already have 5 bytes */
            
            /* Attempt to read the rest immediately */
            if (tcp_socks5_recv_response("tcp_socks5_recv_proxyresp_cb", evloop, socks5_watcher, socks5_watcher->data, context->client_length) != 1) {
                return;
            }
        }
    }

    if (!socks5_proxy_response_check("tcp_socks5_recv_proxyresp_cb", socks5_watcher->data)) {
        tcp_context_release(evloop, context, true);
        return;
    }

    context->client_length = 0;
    
    // ... remainder of function ...

    free(socks5_watcher->data);
    socks5_watcher->data = NULL;

    free(context->client_watcher.data);
    context->client_watcher.data = NULL;

    new_nonblock_pipefd(context->client_pipefd);
    new_nonblock_pipefd(context->socks5_pipefd);

    ev_io_start(evloop, &context->client_watcher);
    ev_set_cb(socks5_watcher, tcp_stream_payload_forward_cb);
    LOGINF("[tcp_socks5_recv_proxyresp_cb] tunnel is ready, start forwarding ...");
}

static void tcp_stream_payload_forward_cb(evloop_t *evloop, evio_t *self_watcher, int revents) {
    bool self_is_client = self_watcher->events & EV_CUSTOM;
    tcp_context_t *context = get_tcpctx_by_watcher(self_watcher);
    evio_t *peer_watcher = self_is_client ? &context->socks5_watcher : &context->client_watcher;

    if (revents & EV_READ) {
        int *self_pipefd = self_is_client ? context->client_pipefd : context->socks5_pipefd;
        ssize_t nrecv = splice(self_watcher->fd, NULL, self_pipefd[1], NULL, TCP_SPLICE_MAXLEN, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nrecv < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[tcp_stream_payload_forward_cb] recv from %s stream: %s", self_is_client ? "client" : "socks5", strerror(errno));
                tcp_context_release(evloop, context, true);
                return;
            }
            goto DO_WRITE; // EAGAIN
        }
        if (nrecv == 0) {
            LOGINF("[tcp_stream_payload_forward_cb] recv FIN from %s stream, release ctx", self_is_client ? "client" : "socks5");
            tcp_context_release(evloop, context, false);
            return;
        }

        ssize_t nsend = splice(self_pipefd[0], NULL, peer_watcher->fd, NULL, nrecv, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nsend < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[tcp_stream_payload_forward_cb] send to %s stream: %s", self_is_client ? "socks5" : "client", strerror(errno));
                tcp_context_release(evloop, context, true);
                return;
            }
            nsend = 0; // EAGAIN
        }
        if (nsend < nrecv) {
            *(self_is_client ? &context->client_length : &context->socks5_length) = (size_t)(nrecv - nsend); // remain_length

            ev_io_stop(evloop, self_watcher);
            ev_io_modify(self_watcher, self_watcher->events & ~EV_READ);
            if (self_watcher->events & EV_WRITE) ev_io_start(evloop, self_watcher);

            ev_io_stop(evloop, peer_watcher);
            ev_io_modify(peer_watcher, peer_watcher->events | EV_WRITE);
            ev_io_start(evloop, peer_watcher);
        }
    }

DO_WRITE:
    if (revents & EV_WRITE) {
        int *peer_pipefd = self_is_client ? context->socks5_pipefd : context->client_pipefd;
        uint16_t remain_length = self_is_client ? context->socks5_length : context->client_length;

        ssize_t nsend = splice(peer_pipefd[0], NULL, self_watcher->fd, NULL, remain_length, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (nsend < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[tcp_stream_payload_forward_cb] send to %s stream: %s", self_is_client ? "client" : "socks5", strerror(errno));
                tcp_context_release(evloop, context, true);
            }
            return;
        }
        if (nsend == 0) return; // IGNORE

        remain_length -= (size_t)nsend;
        *(self_is_client ? &context->socks5_length : &context->client_length) = remain_length;

        if (remain_length == 0) {
            ev_io_stop(evloop, self_watcher);
            ev_io_modify(self_watcher, self_watcher->events & ~EV_WRITE);
            if (self_watcher->events & EV_READ) ev_io_start(evloop, self_watcher);

            ev_io_stop(evloop, peer_watcher);
            ev_io_modify(peer_watcher, peer_watcher->events | EV_READ);
            ev_io_start(evloop, peer_watcher);
        }
    }
}
