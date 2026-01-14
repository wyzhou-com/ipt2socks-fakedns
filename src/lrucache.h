#ifndef IPT2SOCKS_LRUCACHE_H
#define IPT2SOCKS_LRUCACHE_H

#include "uthash.h"
#include "netutils.h"
#include "../libev/ev.h"

typedef struct {
    ip_port_t  client_ipport;
    uint32_t   target_ip;
} udp_fork_key_t;

typedef struct {
    ip_port_t  key_ipport;  // (local) source socket address (Main Key)
    udp_fork_key_t fork_key; // Fork Key (Client + TargetIP)
    ip_port_t  orig_dstaddr; // Original destination address (FakeIP or real IP)
    bool       dest_is_ipv4; // Protocol family flag for orig_dstaddr
    bool       is_forked;    // Is this session in the Fork Table?
    evio_t     tcp_watcher; // .data: len(16bit) | recvbuff
    evio_t     udp_watcher; // .data: len(16bit) | firstmsg
    evtimer_t  idle_timer;
    myhash_hh  hh;
} udp_socks5ctx_t;

typedef struct {
    ip_port_t  key_ipport; // (remote) source socket address
    int        udp_sockfd; // bind the above socket address
    evtimer_t  idle_timer;
    myhash_hh  hh;
} udp_tproxyctx_t;

uint16_t lrucache_get_maxsize(void);
void     lrucache_set_maxsize(uint16_t maxsize);

/* return the removed hashentry pointer */
udp_socks5ctx_t* udp_socks5ctx_add(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry);
udp_socks5ctx_t* udp_socks5ctx_fork_add(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry);
udp_tproxyctx_t* udp_tproxyctx_add(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry);

udp_socks5ctx_t* udp_socks5ctx_get(udp_socks5ctx_t **cache, const ip_port_t *keyptr);
udp_socks5ctx_t* udp_socks5ctx_fork_get(udp_socks5ctx_t **cache, const udp_fork_key_t *keyptr);
udp_tproxyctx_t* udp_tproxyctx_get(udp_tproxyctx_t **cache, const ip_port_t *keyptr);

void udp_socks5ctx_use(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry);
void udp_tproxyctx_use(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry);

void udp_socks5ctx_del(udp_socks5ctx_t **cache, udp_socks5ctx_t *entry);
void udp_tproxyctx_del(udp_tproxyctx_t **cache, udp_tproxyctx_t *entry);

#endif
