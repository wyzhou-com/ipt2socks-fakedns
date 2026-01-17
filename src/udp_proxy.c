#define _GNU_SOURCE
#include "udp_proxy.h"
#include "ctx.h"
#include "netutils.h"
#include "socks5.h"
#include "fakedns.h"
#include "logutils.h"
#include "lrucache.h"
#include "mempool.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Forward declarations for static functions moved from ipt2socks.c */
static void handle_udp_socket_msg(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, ssize_t nrecv, char *buffer);
static void udp_socks5_connect_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents);
static void udp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, evio_t *watcher, int revents);
static void udp_socks5_context_timeout_cb(evloop_t *evloop, evtimer_t *watcher, int revents);
static void udp_tproxy_context_timeout_cb(evloop_t *evloop, evtimer_t *watcher, int revents);


void udp_tproxy_recvmsg_cb(evloop_t *evloop, evio_t *tprecv_watcher, int revents __attribute__((unused))) {
    bool isipv4 = tprecv_watcher->data;
    
    /* Use maximum header size to allow building headers backward from payload */
    const size_t max_headerlen = MAX_SOCKS5_UDP_HEADER;
    
    struct mmsghdr msgs[UDP_BATCH_SIZE];
    struct iovec iovs[UDP_BATCH_SIZE];
    char msg_control_buffers[UDP_BATCH_SIZE][UDP_CTRLMESG_BUFSIZ];
    skaddr6_t skaddrs[UDP_BATCH_SIZE];

    memset(msgs, 0, sizeof(msgs));
    memset(iovs, 0, sizeof(iovs));
    memset(msg_control_buffers, 0, sizeof(msg_control_buffers));

    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        iovs[i].iov_base = (void *)g_udp_batch_buffer[i] + max_headerlen;
        iovs[i].iov_len = UDP_DATAGRAM_MAXSIZ - max_headerlen;
        
        msgs[i].msg_hdr.msg_name = &skaddrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(skaddr6_t); // Use largest size
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_control = msg_control_buffers[i];
        msgs[i].msg_hdr.msg_controllen = UDP_CTRLMESG_BUFSIZ;
    }

    /* non-blocking receive */
    int retval = recvmmsg(tprecv_watcher->fd, msgs, UDP_BATCH_SIZE, MSG_DONTWAIT, NULL);
    
    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
             LOGERR("[udp_tproxy_recvmsg_cb] recvmmsg from udp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }
    
    if (retval == 0) return;
    
    for (int i = 0; i < retval; i++) {
        handle_udp_socket_msg(evloop, tprecv_watcher, &msgs[i].msg_hdr, msgs[i].msg_len, g_udp_batch_buffer[i]);
    }
}

static char *build_socks5_udp_header(char *payload_start, const char *fake_domain, const skaddr6_t *skaddr, bool isipv4, size_t *out_headerlen) {
    char *header_start;
    size_t actual_headerlen;

    if (fake_domain) {
        /* DOMAIN format: [reserved(2)][fragment(1)][addrtype(1)][len(1)][domain(n)][port(2)] */
        size_t domain_len = strlen(fake_domain);
        
        actual_headerlen = 4 + 1 + domain_len + 2;
        header_start = payload_start - actual_headerlen;
        
        /* Build DOMAIN header directly in the reserved space */
        socks5_udp_domainmsg_t *dmsg = (socks5_udp_domainmsg_t *)header_start;
        dmsg->reserved = 0;
        dmsg->fragment = 0;
        dmsg->addrtype = SOCKS5_ADDRTYPE_DOMAIN;
        dmsg->domain_len = (uint8_t)domain_len;
        memcpy(dmsg->domain_str, fake_domain, domain_len);
        memcpy(dmsg->domain_str + domain_len, &((const skaddr4_t *)skaddr)->sin_port, 2);
    } else {
        /* IP format */
        actual_headerlen = isipv4 ? sizeof(socks5_udp4msg_t) : sizeof(socks5_udp6msg_t);
        header_start = payload_start - actual_headerlen;
        
        socks5_udp4msg_t *udp4msg = (socks5_udp4msg_t *)header_start;
        udp4msg->reserved = 0;
        udp4msg->fragment = 0;
        udp4msg->addrtype = isipv4 ? SOCKS5_ADDRTYPE_IPV4 : SOCKS5_ADDRTYPE_IPV6;
        
        if (isipv4) {
            udp4msg->ipaddr4 = ((const skaddr4_t *)skaddr)->sin_addr.s_addr;
            udp4msg->portnum = ((const skaddr4_t *)skaddr)->sin_port;
        } else {
            socks5_udp6msg_t *udp6msg = (socks5_udp6msg_t *)header_start;
            memcpy(&udp6msg->ipaddr6, &skaddr->sin6_addr.s6_addr, IP6BINLEN);
            udp6msg->portnum = skaddr->sin6_port;
        }
    }
    
    if (out_headerlen) *out_headerlen = actual_headerlen;
    return header_start;
}

static void handle_udp_socket_msg(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, ssize_t nrecv, char *buffer) {
    bool isipv4 = tprecv_watcher->data;
    skaddr6_t skaddr; char ipstr[IP6STRLEN]; portno_t portno;
    
    /* 
     * Memory layout optimization:
     * buffer points to start of g_udp_batch_buffer[i]
     * Payload is at fixed position: buffer + MAX_SOCKS5_UDP_HEADER
     * Header is built backward from payload position
     */
    char *payload_start = buffer + MAX_SOCKS5_UDP_HEADER;

    /* Restore skaddr from msg->msg_name (sender address) */
    if (msg->msg_namelen == sizeof(skaddr4_t)) {
        memcpy(&skaddr, msg->msg_name, sizeof(skaddr4_t));
    } else {
        memcpy(&skaddr, msg->msg_name, sizeof(skaddr6_t));
    }

    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[udp_tproxy_recvmsg_cb] recv from %s#%hu, nrecv:%zd", ipstr, portno, nrecv);
    }

    ip_port_t key_ipport;
    memset(&key_ipport, 0, sizeof(key_ipport));
    if (isipv4) {
        key_ipport.ip.ip4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        key_ipport.port = ((skaddr4_t *)&skaddr)->sin_port;
    } else {
        memcpy(&key_ipport.ip.ip6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
        key_ipport.port = skaddr.sin6_port;
    }

    if (!get_udp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, msg, &skaddr)) {
        LOGERR("[udp_tproxy_recvmsg_cb] destination address not found in udp msg");
        return;
    }

    /* FakeDNS reverse lookup for domain resolution */
    const char *fake_domain = NULL;
    char domain_buf[256];
    if ((g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        uint32_t target_ip = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        if (fakedns_reverse_lookup(target_ip, domain_buf, sizeof(domain_buf))) {
            fake_domain = domain_buf;
            LOGINF("[udp_tproxy_recvmsg_cb] fakedns hit: %u.%u.%u.%u -> %s",
                   ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                   ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                   fake_domain);
        }
    }

    /* Build SOCKS5 UDP header backward from payload position (zero-copy optimization) */
    char *header_start;
    size_t actual_headerlen;
    
    header_start = build_socks5_udp_header(payload_start, fake_domain, &skaddr, isipv4, &actual_headerlen);

    udp_socks5ctx_t *context = NULL;
    bool force_fork = false;
    uint32_t target_ip = 0;
    
    if (isipv4) target_ip = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;

    if (fake_domain && (g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        udp_fork_key_t fork_key;
        memset(&fork_key, 0, sizeof(fork_key));
        fork_key.client_ipport = key_ipport;
        fork_key.target_ip = target_ip;
        
        /* 1. Check Fork Table first (Symmetric Path) */
        context = udp_socks5ctx_fork_get(&g_udp_fork_table, &fork_key);
        
        if (!context) {
            /* 2. Check Main Table (Cone Path) */
            udp_socks5ctx_t *main_ctx = udp_socks5ctx_get(&g_udp_socks5ctx_table, &key_ipport);
            if (main_ctx) {
                /* Check if Target Matches */
                if (main_ctx->dest_is_ipv4 && main_ctx->orig_dstaddr.ip.ip4 == target_ip) {
                    /* Match! Safe to reuse Main Context */
                    context = main_ctx;
                } else {
                    /* Collision detected! Client reusing port for diff Target. Force Fork. */
                    force_fork = true;
                    LOGINF("[udp_tproxy_recvmsg_cb] collision detected for %s, forcing fork", fake_domain);
                }
            }
        }
    } else {
        context = udp_socks5ctx_get(&g_udp_socks5ctx_table, &key_ipport);
    }

    if (!context) {
        int tcp_sockfd = new_tcp_connect_sockfd(g_server_skaddr.sin6_family, g_tcp_syncnt_max);
        const void *tfo_data = (g_options & OPT_ENABLE_TFO_CONNECT) ? &g_socks5_auth_request : NULL;
        uint16_t tfo_datalen = (g_options & OPT_ENABLE_TFO_CONNECT) ? sizeof(socks5_authreq_t) : 0;
        ssize_t tfo_nsend = -1; /* if tfo connect succeed: tfo_nsend >= 0 */

        if (!tcp_connect(tcp_sockfd, &g_server_skaddr, tfo_data, tfo_datalen, &tfo_nsend)) {
            LOGERR("[udp_tproxy_recvmsg_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
            close(tcp_sockfd);
            return;
        }
        if (tfo_nsend >= 0) {
            LOGINF("[udp_tproxy_recvmsg_cb] tfo send to %s#%hu, nsend:%zd", g_server_ipstr, g_server_portno, tfo_nsend);
        } else {
            LOGINF("[udp_tproxy_recvmsg_cb] try to connect to %s#%hu ...", g_server_ipstr, g_server_portno);
        }

        context = malloc(sizeof(*context));
        memcpy(&context->key_ipport, &key_ipport, sizeof(key_ipport));

        // Save original destination and protocol family
        context->dest_is_ipv4 = isipv4;
        if (isipv4) {
            context->orig_dstaddr.ip.ip4 = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
            context->orig_dstaddr.port = ((skaddr4_t *)&skaddr)->sin_port;
        } else {
            memcpy(&context->orig_dstaddr.ip.ip6, &skaddr.sin6_addr.s6_addr, IP6BINLEN);
            context->orig_dstaddr.port = skaddr.sin6_port;
        }

        evio_t *watcher = &context->tcp_watcher;
        if (tfo_nsend >= 0 && (size_t)tfo_nsend >= tfo_datalen) {
            ev_io_init(watcher, udp_socks5_recv_authresp_cb, tcp_sockfd, EV_READ);
            tfo_nsend = 0;
        } else {
            ev_io_init(watcher, tfo_nsend >= 0 ? udp_socks5_send_authreq_cb : udp_socks5_connect_cb, tcp_sockfd, EV_WRITE);
            tfo_nsend = tfo_nsend >= 0 ? tfo_nsend : 0;
        }
        ev_io_start(evloop, watcher);
        context->tcp_watcher.data = malloc(2 + sizeof(socks5_ipv6resp_t));
        *(uint16_t *)context->tcp_watcher.data = tfo_nsend; /* nsend or nrecv */

        /* tunnel not ready if udp_watcher->data != NULL */
        size_t node_size = sizeof(udp_packet_node_t) + actual_headerlen + nrecv;
        udp_packet_node_t *node = mempool_alloc_sized(g_udp_packet_pool, node_size);
        if (!node) {
            LOGERR("[udp_tproxy_recvmsg_cb] mempool_alloc_sized failed for %zu bytes", node_size);
            ev_io_stop(evloop, watcher);
            close(tcp_sockfd);
            free(context->tcp_watcher.data);
            free(context);
            return;
        }
        node->next = NULL;
        node->len = actual_headerlen + nrecv;
        memcpy(node->data, header_start, actual_headerlen + nrecv);
        
        udp_packet_queue_t *queue = malloc(sizeof(udp_packet_queue_t));
        queue->head = node;
        queue->tail = node;
        queue->count = 1;
        context->udp_watcher.data = queue;

        evtimer_t *timer = &context->idle_timer;
        ev_timer_init(timer, udp_socks5_context_timeout_cb, 0, g_udp_idletimeout_sec);
        timer->data = (void *)sizeof(socks5_ipv4resp_t); // response_length

        udp_socks5ctx_t *del_context = NULL;
        if (force_fork) {
            context->is_forked = true;
            memset(&context->fork_key, 0, sizeof(context->fork_key));
            context->fork_key.client_ipport = key_ipport;
            context->fork_key.target_ip = target_ip;
            del_context = udp_socks5ctx_fork_add(&g_udp_fork_table, context);
        } else {
            context->is_forked = false;
            del_context = udp_socks5ctx_add(&g_udp_socks5ctx_table, context);
        }

        if (del_context) ev_invoke(evloop, &del_context->idle_timer, EV_CUSTOM);
        return;
    }
    
    /* Tunnel not ready if udp_watcher.data != NULL */
    if (context->udp_watcher.data) {
        udp_packet_queue_t *queue = context->udp_watcher.data;
        
        if (queue->count >= UDP_QUEUE_MAX_DEPTH) {
            LOGWAR("[udp_tproxy_recvmsg_cb] packet queue full (%zu), dropping this msg", queue->count);
            return;
        }

        LOGINF("[udp_tproxy_recvmsg_cb] tunnel is not ready, buffering this msg (queue: %zu)", queue->count);
        
        size_t node_size = sizeof(udp_packet_node_t) + actual_headerlen + nrecv;
        udp_packet_node_t *node = mempool_alloc_sized(g_udp_packet_pool, node_size);
        if (!node) {
            LOGERR("[udp_tproxy_recvmsg_cb] mempool_alloc_sized failed for %zu bytes", node_size);
            return;
        }
        node->next = NULL;
        node->len = actual_headerlen + nrecv;
        memcpy(node->data, header_start, actual_headerlen + nrecv);

        /* Append to the end of the list (O(1)) */
        if (queue->tail) {
            queue->tail->next = node;
            queue->tail = node;
        } else {
            queue->head = node;
            queue->tail = node;
        }
        queue->count++;
        return;
    }

    ev_timer_again(evloop, &context->idle_timer);

    nrecv = send(context->udp_watcher.fd, header_start, actual_headerlen + nrecv, 0);
    if (nrecv < 0) {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGERR("[udp_tproxy_recvmsg_cb] send to %s#%hu: %s", ipstr, portno, strerror(errno));
        return;
    }
    if (fake_domain) {
        portno = ntohs(((skaddr4_t *)&skaddr)->sin_port);
        LOGINF("[udp_tproxy_recvmsg_cb] send to %s#%hu, nsend:%zd", fake_domain, portno, nrecv);
    } else {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF("[udp_tproxy_recvmsg_cb] send to %s#%hu, nsend:%zd", ipstr, portno, nrecv);
    }
}

static inline udp_socks5ctx_t* get_udpsk5ctx_by_tcp(evio_t *tcp_watcher) {
    return (void *)tcp_watcher - offsetof(udp_socks5ctx_t, tcp_watcher);
}

static inline void udp_socks5ctx_release(evloop_t *evloop, udp_socks5ctx_t *context) {
    ev_invoke(evloop, &context->idle_timer, EV_CUSTOM);
}

static void udp_socks5_connect_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (tcp_has_error(tcp_watcher->fd)) {
        LOGERR("[udp_socks5_connect_cb] connect to %s#%hu: %s", g_server_ipstr, g_server_portno, strerror(errno));
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return;
    }
    LOGINF("[udp_socks5_connect_cb] connect to %s#%hu succeeded", g_server_ipstr, g_server_portno);
    ev_set_cb(tcp_watcher, udp_socks5_send_authreq_cb);
    ev_invoke(evloop, tcp_watcher, EV_WRITE);
}

/* return: -1(error_occurred); 0(partial_sent); 1(completely_sent) */
static int udp_socks5_send_request(const char *funcname, evloop_t *evloop, evio_t *tcp_watcher, const void *data, size_t datalen) {
    uint16_t *nsend = tcp_watcher->data;
    ssize_t n = send(tcp_watcher->fd, data + *nsend, datalen - *nsend, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] send to %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
            return -1;
        }
        return 0;
    }
    LOGINF("[%s] send to %s#%hu, nsend:%zd", funcname, g_server_ipstr, g_server_portno, n);
    *nsend += (size_t)n;
    if (*nsend >= datalen) {
        *nsend = 0;
        return 1;
    }
    return 0;
}

/* return: -1(error_occurred); 0(partial_recv); 1(completely_recv) */
static int udp_socks5_recv_response(const char *funcname, evloop_t *evloop, evio_t *tcp_watcher, void *data, size_t datalen) {
    uint16_t *nrecv = tcp_watcher->data;
    ssize_t n = recv(tcp_watcher->fd, data + *nrecv, datalen - *nrecv, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[%s] recv from %s#%hu: %s", funcname, g_server_ipstr, g_server_portno, strerror(errno));
            udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
            return -1;
        }
        return 0;
    }
    if (n == 0) {
        LOGERR("[%s] recv from %s#%hu: connection is closed", funcname, g_server_ipstr, g_server_portno);
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return -1;
    }
    LOGINF("[%s] recv from %s#%hu, nrecv:%zd", funcname, g_server_ipstr, g_server_portno, n);
    *nrecv += (size_t)n;
    if (*nrecv >= datalen) {
        *nrecv = 0;
        return 1;
    }
    return 0;
}

static void udp_socks5_send_authreq_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (udp_socks5_send_request("udp_socks5_send_authreq_cb", evloop, tcp_watcher, &g_socks5_auth_request, sizeof(socks5_authreq_t)) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_authresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_authresp_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (udp_socks5_recv_response("udp_socks5_recv_authresp_cb", evloop, tcp_watcher, tcp_watcher->data + 2, sizeof(socks5_authresp_t)) != 1) {
        return;
    }
    if (!socks5_auth_response_check("udp_socks5_recv_authresp_cb", tcp_watcher->data + 2)) {
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return;
    }
    const void *data; uint16_t datalen;
    if (g_socks5_usrpwd_requestlen) {
        data = &g_socks5_usrpwd_request;
        datalen = g_socks5_usrpwd_requestlen;
    } else {
        udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
        bool isipv4 = ((socks5_udp4msg_t *)((udp_packet_queue_t *)context->udp_watcher.data)->head->data)->addrtype == SOCKS5_ADDRTYPE_IPV4;
        data = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
        datalen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    }
    int ret = udp_socks5_send_request("udp_socks5_recv_authresp_cb", evloop, tcp_watcher, data, datalen);
    if (ret == 1) {
        ev_set_cb(tcp_watcher, g_socks5_usrpwd_requestlen ? udp_socks5_recv_usrpwdresp_cb : udp_socks5_recv_proxyresp_cb);
    } else if (ret == 0) {
        ev_io_stop(evloop, tcp_watcher);
        ev_io_init(tcp_watcher, g_socks5_usrpwd_requestlen ? udp_socks5_send_usrpwdreq_cb : udp_socks5_send_proxyreq_cb, tcp_watcher->fd, EV_WRITE);
        ev_io_start(evloop, tcp_watcher);
    }
}

static void udp_socks5_send_usrpwdreq_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (udp_socks5_send_request("udp_socks5_send_usrpwdreq_cb", evloop, tcp_watcher, &g_socks5_usrpwd_request, g_socks5_usrpwd_requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_usrpwdresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_usrpwdresp_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    if (udp_socks5_recv_response("udp_socks5_recv_usrpwdresp_cb", evloop, tcp_watcher, tcp_watcher->data + 2, sizeof(socks5_usrpwdresp_t)) != 1) {
        return;
    }
    if (!socks5_usrpwd_response_check("udp_socks5_recv_usrpwdresp_cb", tcp_watcher->data + 2)) {
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
        return;
    }
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    bool isipv4 = ((socks5_udp4msg_t *)((udp_packet_queue_t *)context->udp_watcher.data)->head->data)->addrtype == SOCKS5_ADDRTYPE_IPV4;
    const void *data = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
    uint16_t datalen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    int ret = udp_socks5_send_request("udp_socks5_recv_usrpwdresp_cb", evloop, tcp_watcher, data, datalen);
    if (ret == 1) {
        ev_set_cb(tcp_watcher, udp_socks5_recv_proxyresp_cb);
    } else if (ret == 0) {
        ev_io_stop(evloop, tcp_watcher);
        ev_io_init(tcp_watcher, udp_socks5_send_proxyreq_cb, tcp_watcher->fd, EV_WRITE);
        ev_io_start(evloop, tcp_watcher);
    }
}

static void udp_socks5_send_proxyreq_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    bool isipv4 = ((socks5_udp4msg_t *)((udp_packet_queue_t *)context->udp_watcher.data)->head->data)->addrtype == SOCKS5_ADDRTYPE_IPV4;
    const void *request = isipv4 ? (void *)&G_SOCKS5_UDP4_REQUEST : (void *)&G_SOCKS5_UDP6_REQUEST;
    uint16_t requestlen = isipv4 ? sizeof(socks5_ipv4req_t) : sizeof(socks5_ipv6req_t);
    if (udp_socks5_send_request("udp_socks5_send_proxyreq_cb", evloop, tcp_watcher, request, requestlen) != 1) {
        return;
    }
    ev_io_stop(evloop, tcp_watcher);
    ev_io_init(tcp_watcher, udp_socks5_recv_proxyresp_cb, tcp_watcher->fd, EV_READ);
    ev_io_start(evloop, tcp_watcher);
}

static void udp_socks5_recv_proxyresp_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    udp_socks5ctx_t *context = get_udpsk5ctx_by_tcp(tcp_watcher);
    if (udp_socks5_recv_response("udp_socks5_recv_proxyresp_cb", evloop, tcp_watcher, tcp_watcher->data + 2, (uintptr_t)context->idle_timer.data) != 1) {
        return;
    }
    if ((uintptr_t)context->idle_timer.data == sizeof(socks5_ipv4resp_t)) {
        if (!socks5_proxy_response_check("udp_socks5_recv_proxyresp_cb", tcp_watcher->data + 2)) {
            udp_socks5ctx_release(evloop, context);
            return;
        }
        if (((socks5_ipv4resp_t *)(tcp_watcher->data + 2))->addrtype == SOCKS5_ADDRTYPE_IPV6) {
            context->idle_timer.data = (void *)sizeof(socks5_ipv6resp_t); // response_length
            *(uint16_t *)tcp_watcher->data = sizeof(socks5_ipv4resp_t); // response_nrecv
            return;
        } else if (((socks5_ipv4resp_t *)(tcp_watcher->data + 2))->addrtype == SOCKS5_ADDRTYPE_DOMAIN) {
            uint8_t domain_len = ((socks5_domainresp_t *)(tcp_watcher->data + 2))->domain_len;
            size_t total_len = sizeof(socks5_domainreq_t) + domain_len + 2; // header(4) + len(1) + domain(n) + port(2)
            
            if (total_len > (uintptr_t)context->idle_timer.data) {
                // Need to expand buffer
                void *new_buf = realloc(tcp_watcher->data, 2 + total_len);
                if (!new_buf) {
                     LOGERR("[udp_socks5_recv_proxyresp_cb] realloc failed");
                     udp_socks5ctx_release(evloop, context);
                     return;
                }
                tcp_watcher->data = new_buf;
                context->idle_timer.data = (void *)total_len;
                *(uint16_t *)tcp_watcher->data = sizeof(socks5_ipv4resp_t); // response_nrecv
                return;
            }
        }
    }
    portno_t relay_port;
    uint8_t atype = ((socks5_ipv4resp_t *)(tcp_watcher->data + 2))->addrtype;
    if (atype == SOCKS5_ADDRTYPE_IPV4) {
        relay_port = ((socks5_ipv4resp_t *)(tcp_watcher->data + 2))->portnum;
    } else if (atype == SOCKS5_ADDRTYPE_IPV6) {
        relay_port = ((socks5_ipv6resp_t *)(tcp_watcher->data + 2))->portnum;
    } else if (atype == SOCKS5_ADDRTYPE_DOMAIN) {
        socks5_domainresp_t *dresp = (void *)(tcp_watcher->data + 2);
        memcpy(&relay_port, dresp->domain_str + dresp->domain_len, 2);
    } else {
        LOGERR("[udp_socks5_recv_proxyresp_cb] unsupported address type: 0x%02x", atype);
        udp_socks5ctx_release(evloop, context);
        return;
    }

    /* the address is usually the same as the socks5 server address (except for the port) */
    skaddr6_t relay_addr;
    memcpy(&relay_addr, &g_server_skaddr, sizeof(g_server_skaddr));

    /* update the port to the udp relay port */
    bool relay_isipv4 = relay_addr.sin6_family == AF_INET;
    if (relay_isipv4)
        ((skaddr4_t *)&relay_addr)->sin_port = relay_port;
    else
        relay_addr.sin6_port = relay_port;

    /* connect to the socks5 udp relay endpoint */
    int udp_sockfd = new_udp_normal_sockfd(relay_addr.sin6_family);
    if (connect(udp_sockfd, (void *)&relay_addr, relay_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
        char ipstr[IP6STRLEN]; portno_t portno;
        parse_socket_addr(&relay_addr, ipstr, &portno);
        LOGERR("[udp_socks5_recv_proxyresp_cb] connect to udp://%s#%u: %s", ipstr, (unsigned)portno, strerror(errno));
        udp_socks5ctx_release(evloop, context);
        close(udp_sockfd);
        return;
    }

    udp_packet_queue_t *queue = context->udp_watcher.data;
    udp_packet_node_t *curr = queue->head;
    while (curr) {
        ssize_t nsend = send(udp_sockfd, curr->data, curr->len, 0);
        if (nsend < 0 || g_verbose) {
            char ipstr[IP6STRLEN]; portno_t portno;
            uint8_t addrtype = ((socks5_udp4msg_t *)curr->data)->addrtype;
            
            if (addrtype == SOCKS5_ADDRTYPE_IPV4) {
                socks5_udp4msg_t *udp4msg = (void *)curr->data;
                inet_ntop(AF_INET, &udp4msg->ipaddr4, ipstr, IP6STRLEN);
                portno = ntohs(udp4msg->portnum);
            } else if (addrtype == SOCKS5_ADDRTYPE_DOMAIN) {
                /* Domain format: extract domain and port for logging */
                uint8_t *msg = curr->data;
                uint8_t domain_len = msg[4];
                memcpy(ipstr, msg + 5, domain_len);
                ipstr[domain_len] = '\0';
                memcpy(&portno, msg + 5 + domain_len, 2);
                portno = ntohs(portno);
            } else {
                socks5_udp6msg_t *udp6msg = (void *)curr->data;
                inet_ntop(AF_INET6, &udp6msg->ipaddr6, ipstr, IP6STRLEN);
                portno = ntohs(udp6msg->portnum);
            }
            if (nsend < 0) {
                LOGERR("[udp_socks5_recv_proxyresp_cb] send to %s#%hu: %s", ipstr, portno, strerror(errno));
            } else {
                LOGINF("[udp_socks5_recv_proxyresp_cb] send to %s#%hu, nsend:%zd", ipstr, portno, nsend);
            }
        }
        udp_packet_node_t *next = curr->next;
        size_t node_size = sizeof(udp_packet_node_t) + curr->len;
        mempool_free_sized(g_udp_packet_pool, curr, node_size);
        curr = next;
    }
    
    free(context->udp_watcher.data);
    context->udp_watcher.data = NULL;

    ev_set_cb(tcp_watcher, udp_socks5_recv_tcpmessage_cb);
    free(tcp_watcher->data);
    tcp_watcher->data = NULL;

    evio_t *watcher = &context->udp_watcher;
    ev_io_init(watcher, udp_socks5_recv_udpmessage_cb, udp_sockfd, EV_READ);
    ev_io_start(evloop, watcher);

    ev_timer_again(evloop, &context->idle_timer);
    if (context->is_forked) {
        udp_socks5ctx_use(&g_udp_fork_table, context);
    } else {
        udp_socks5ctx_use(&g_udp_socks5ctx_table, context);
    }
}

static void udp_socks5_recv_tcpmessage_cb(evloop_t *evloop, evio_t *tcp_watcher, int revents __attribute__((unused))) {
    ssize_t nrecv = recv(tcp_watcher->fd, (char [1]){0}, 1, 0);
    if (nrecv > 0) {
        LOGERR("[udp_socks5_recv_tcpmessage_cb] recv unknown msg from socks5 server, release ctx");
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
    } else if (nrecv == 0) {
        LOGINF("[udp_socks5_recv_tcpmessage_cb] recv FIN from socks5 server, release ctx");
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
        LOGERR("[udp_socks5_recv_tcpmessage_cb] recv from socks5 server: %s", strerror(errno));
        udp_socks5ctx_release(evloop, get_udpsk5ctx_by_tcp(tcp_watcher));
    }
}


static void handle_udp_socks5_response(evloop_t *evloop, udp_socks5ctx_t *socks5ctx, char *buffer, ssize_t nrecv) {
    if ((size_t)nrecv < sizeof(socks5_udp4msg_t)) {
        LOGERR("[udp_socks5_recv_udpmessage_cb] recv from socks5 server: message too small");
        return;
    }
    socks5_udp4msg_t *udp4msg = (void *)buffer;
    bool isipv4 = udp4msg->addrtype == SOCKS5_ADDRTYPE_IPV4;
    bool isipv6 = udp4msg->addrtype == SOCKS5_ADDRTYPE_IPV6;
    bool isdomain = udp4msg->addrtype == SOCKS5_ADDRTYPE_DOMAIN;

    /* Parse address and calculate header length */
    size_t headerlen;
    char domain_buf[256];
    uint8_t domain_len = 0;

    if (isipv4) {
        headerlen = sizeof(socks5_udp4msg_t);
        if ((size_t)nrecv < headerlen) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] recv from socks5 server: message too small");
            return;
        }
    } else if (isipv6) {
        headerlen = sizeof(socks5_udp6msg_t);
        if ((size_t)nrecv < headerlen) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] recv from socks5 server: message too small");
            return;
        }
    } else if (isdomain) {
        /* Domain format: [reserved(2)] [fragment(1)] [addrtype(1)] [len(1)] [domain(n)] [port(2)] */
        if ((size_t)nrecv < 5) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] recv from socks5 server: domain message too small");
            return;
        }
        domain_len = ((uint8_t *)buffer)[4];
        headerlen = 4 + 1 + domain_len + 2;
        if ((size_t)nrecv < headerlen) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] recv from socks5 server: domain message truncated");
            return;
        }
        
        /* Optimization: Parse domain once and reuse */
        memcpy(domain_buf, (uint8_t *)buffer + 5, domain_len);
        domain_buf[domain_len] = '\0';
        LOGINF("[udp_socks5_recv_udpmessage_cb] recv domain response: %s, nrecv:%zd", domain_buf, nrecv);
    } else {
        LOGERR("[udp_socks5_recv_udpmessage_cb] unsupported address type: 0x%02x", udp4msg->addrtype);
        return;
    }

    /* Determine source address and port for the response packet */
    ip_port_t fromipport;
    bool dest_isipv4;

    if (g_options & OPT_ENABLE_FAKEDNS) {
        /* [FakeDNS Enabled] ALWAYS use saved original destination (FakeIP) to maintain mapping */
        /* This handles IPv4, IPv6, and Domain responses by preserving the client's perspective */
        fromipport = socks5ctx->orig_dstaddr;
        dest_isipv4 = socks5ctx->dest_is_ipv4;
    } else {
        /* [FakeDNS Disabled] Use actual source address from SOCKS5 payload */
        if (isipv4) {
            fromipport.ip.ip4 = udp4msg->ipaddr4;
            fromipport.port = udp4msg->portnum;
            dest_isipv4 = true;
        } else if (isipv6) {
            socks5_udp6msg_t *udp6msg = (void *)buffer;
            memcpy(&fromipport.ip.ip6, &udp6msg->ipaddr6, IP6BINLEN);
            fromipport.port = udp6msg->portnum;
            dest_isipv4 = false;
        } else {
            /* Domain response without FakeDNS: cannot TProxy bind to domain */
            LOGWAR("[udp_socks5_recv_udpmessage_cb] domain response received but FakeDNS disabled, dropping");
            return;
        }
    }

    char ipstr[IP6STRLEN]; portno_t portno;

    udp_tproxyctx_t *tproxyctx = udp_tproxyctx_get(&g_udp_tproxyctx_table, &fromipport);
    if (!tproxyctx) {
        skaddr6_t fromskaddr = {0};
        if (dest_isipv4) {
            skaddr4_t *addr = (void *)&fromskaddr;
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = fromipport.ip.ip4;
            addr->sin_port = fromipport.port;
        } else {
            fromskaddr.sin6_family = AF_INET6;
            memcpy(&fromskaddr.sin6_addr.s6_addr, &fromipport.ip.ip6, IP6BINLEN);
            fromskaddr.sin6_port = fromipport.port;
        }
        int tproxy_sockfd = new_udp_tpsend_sockfd(dest_isipv4 ? AF_INET : AF_INET6);
        if (bind(tproxy_sockfd, (void *)&fromskaddr, dest_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
            if (dest_isipv4) {
                 inet_ntop(AF_INET, &((skaddr4_t*)&fromskaddr)->sin_addr, ipstr, sizeof(ipstr));
                 portno = ntohs(((skaddr4_t*)&fromskaddr)->sin_port);
            } else {
                 inet_ntop(AF_INET6, &fromskaddr.sin6_addr, ipstr, sizeof(ipstr));
                 portno = ntohs(fromskaddr.sin6_port);
            }
            LOGERR("[udp_socks5_recv_udpmessage_cb] bind tproxy reply address %s#%d: %s", ipstr, portno, strerror(errno));
            close(tproxy_sockfd);
            return;
        }
        tproxyctx = malloc(sizeof(*tproxyctx));
        memcpy(&tproxyctx->key_ipport, &fromipport, sizeof(fromipport));
        tproxyctx->udp_sockfd = tproxy_sockfd;
        evtimer_t *timer = &tproxyctx->idle_timer;
        ev_timer_init(timer, udp_tproxy_context_timeout_cb, 0, g_udp_idletimeout_sec);
        udp_tproxyctx_t *del_context = udp_tproxyctx_add(&g_udp_tproxyctx_table, tproxyctx);
        if (del_context) ev_invoke(evloop, &del_context->idle_timer, EV_CUSTOM);
    }
    ev_timer_again(evloop, &tproxyctx->idle_timer);

    ip_port_t *toipport = &socks5ctx->key_ipport;
    skaddr6_t toskaddr = {0};
    if (dest_isipv4) {
        skaddr4_t *addr = (void *)&toskaddr;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = toipport->ip.ip4;
        addr->sin_port = toipport->port;
    } else {
        toskaddr.sin6_family = AF_INET6;
        memcpy(&toskaddr.sin6_addr.s6_addr, &toipport->ip.ip6, IP6BINLEN);
        toskaddr.sin6_port = toipport->port;
    }

    nrecv = sendto(tproxyctx->udp_sockfd, (void *)buffer + headerlen, nrecv - headerlen, 0, (void *)&toskaddr, dest_isipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t));
    if (nrecv < 0) {
        parse_socket_addr(&toskaddr, ipstr, &portno);
        LOGERR("[udp_socks5_recv_udpmessage_cb] send to %s#%hu: %s", ipstr, portno, strerror(errno));
        return;
    }
    parse_socket_addr(&toskaddr, ipstr, &portno);
#ifdef ENABLE_SENDTO_LOG
    LOGINF("[udp_socks5_recv_udpmessage_cb] send to %s#%hu, nsend:%zd", ipstr, portno, nrecv);
#endif
}

static void udp_socks5_recv_udpmessage_cb(evloop_t *evloop, evio_t *udp_watcher, int revents __attribute__((unused))) {
    udp_socks5ctx_t *socks5ctx = (void *)udp_watcher - offsetof(udp_socks5ctx_t, udp_watcher);
    
    struct mmsghdr msgs[UDP_BATCH_SIZE];
    struct iovec iovs[UDP_BATCH_SIZE];
    
    memset(msgs, 0, sizeof(msgs));
    memset(iovs, 0, sizeof(iovs));
    
    /* Prepare for recvmmsg batch receive */
    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        iovs[i].iov_base = g_udp_batch_buffer[i];
        iovs[i].iov_len = UDP_DATAGRAM_MAXSIZ;
        
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = NULL; /* Connected socket, no address needed */
        msgs[i].msg_hdr.msg_namelen = 0;
    }

    int retval = recvmmsg(udp_watcher->fd, msgs, UDP_BATCH_SIZE, MSG_DONTWAIT, NULL);
    
    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_socks5_recv_udpmessage_cb] recvmmsg: %s", strerror(errno));
        }
        return;
    }
    
    for (int i = 0; i < retval; i++) {
        /* Process each received packet */
        handle_udp_socks5_response(evloop, socks5ctx, g_udp_batch_buffer[i], msgs[i].msg_len);
    }
    
    /* Optimization: Update LRU only once per batch */
    if (retval > 0) {
        if (socks5ctx->is_forked) {
            udp_socks5ctx_use(&g_udp_fork_table, socks5ctx);
        } else {
            udp_socks5ctx_use(&g_udp_socks5ctx_table, socks5ctx);
        }
        ev_timer_again(evloop, &socks5ctx->idle_timer);
    }
}

static void udp_socks5_context_timeout_cb(evloop_t *evloop, evtimer_t *idle_timer, int revents) {
    LOGINF("[udp_socks5_context_timeout_cb] context will be released, reason: %s", revents & EV_CUSTOM ? "manual" : "timeout");

    udp_socks5ctx_t *context = (void *)idle_timer - offsetof(udp_socks5ctx_t, idle_timer);
    if (context->is_forked) {
        udp_socks5ctx_del(&g_udp_fork_table, context);
    } else {
        udp_socks5ctx_del(&g_udp_socks5ctx_table, context);
    }

    ev_timer_stop(evloop, idle_timer);

    ev_io_stop(evloop, &context->tcp_watcher);
    close(context->tcp_watcher.fd);
    free(context->tcp_watcher.data);

    if (context->udp_watcher.data) {
        udp_packet_queue_t *queue = context->udp_watcher.data;
        udp_packet_node_t *curr = queue->head;
        while (curr) {
            udp_packet_node_t *next = curr->next;
            size_t node_size = sizeof(udp_packet_node_t) + curr->len;
            mempool_free_sized(g_udp_packet_pool, curr, node_size);
            curr = next;
        }
        free(queue);
        context->udp_watcher.data = NULL;
    } else {
        ev_io_stop(evloop, &context->udp_watcher);
        close(context->udp_watcher.fd);
    }

    free(context);
}

static void udp_tproxy_context_timeout_cb(evloop_t *evloop, evtimer_t *idle_timer, int revents) {
    LOGINF("[udp_tproxy_context_timeout_cb] context will be released, reason: %s", revents & EV_CUSTOM ? "manual" : "timeout");

    udp_tproxyctx_t *context = (void *)idle_timer - offsetof(udp_tproxyctx_t, idle_timer);
    udp_tproxyctx_del(&g_udp_tproxyctx_table, context);

    ev_timer_stop(evloop, idle_timer);
    close(context->udp_sockfd);
    free(context);
}

void udp_dns_recv_cb(evloop_t *evloop, evio_t *watcher, int revents) {
    socklen_t addrlen = sizeof(skaddr4_t);
    skaddr4_t addr;
    
    ssize_t nrecv = recvfrom(watcher->fd, g_udp_batch_buffer[0], UDP_DATAGRAM_MAXSIZ, 0, (struct sockaddr *)&addr, &addrlen);
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_dns_recv_cb] recvfrom: %s", strerror(errno));
        }
        return;
    }
    
    // Process Query
    size_t nresp = fakedns_process_query((uint8_t*)g_udp_batch_buffer[0], nrecv, (uint8_t*)g_udp_batch_buffer[0], UDP_DATAGRAM_MAXSIZ);
    
    if (nresp > 0) {
        if (sendto(watcher->fd, g_udp_batch_buffer[0], nresp, 0, (struct sockaddr *)&addr, addrlen) < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[udp_dns_recv_cb] sendto: %s", strerror(errno));
            }
        }
    }
}
