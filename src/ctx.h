#ifndef IPT2SOCKS_CTX_H
#define IPT2SOCKS_CTX_H

#include <stdbool.h>
#include <stdint.h>
#include "netutils.h"
#include "lrucache.h"
#include "mempool.h"

#define UDP_BATCH_SIZE 64

enum {
    OPT_ENABLE_TCP         = 0x01 << 0, // enable tcp proxy
    OPT_ENABLE_UDP         = 0x01 << 1, // enable udp proxy
    OPT_ENABLE_IPV4        = 0x01 << 2, // enable ipv4 proxy
    OPT_ENABLE_IPV6        = 0x01 << 3, // enable ipv6 proxy
    OPT_TCP_USE_REDIRECT   = 0x01 << 4, // use redirect instead of tproxy (used by tcp)
    OPT_ALWAYS_REUSE_PORT  = 0x01 << 5, // always enable so_reuseport (since linux 3.9+)
    OPT_ENABLE_TFO_ACCEPT  = 0x01 << 6, // enable tcp_fastopen for listen socket (server tfo)
    OPT_ENABLE_TFO_CONNECT = 0x01 << 7, // enable tcp_fastopen for connect socket (client tfo)
    OPT_ENABLE_FAKEDNS     = 0x01 << 8, // enable fakedns feature
};

extern bool     g_verbose;
extern uint16_t g_options;
extern uint8_t  g_nthreads;

extern char      g_bind_ipstr4[IP4STRLEN];
extern char      g_bind_ipstr6[IP6STRLEN];
extern portno_t  g_bind_portno;
extern skaddr4_t g_bind_skaddr4;
extern skaddr6_t g_bind_skaddr6;

extern char      g_server_ipstr[IP6STRLEN];
extern portno_t  g_server_portno;
extern skaddr6_t g_server_skaddr;

extern uint8_t g_tcp_syncnt_max;

extern uint16_t g_udp_idletimeout_sec;
extern __thread udp_socks5ctx_t *g_udp_socks5ctx_table;
extern __thread udp_socks5ctx_t *g_udp_fork_table;
extern __thread udp_tproxyctx_t *g_udp_tproxyctx_table;
extern __thread char    g_udp_batch_buffer[UDP_BATCH_SIZE][UDP_DATAGRAM_MAXSIZ];
extern __thread memory_pool_t *g_udp_packet_pool;
extern __thread memory_pool_t *g_udp_context_pool;
extern __thread memory_pool_t *g_tcp_context_pool;
extern __thread void          *g_tcp_session_head;

extern char      g_fakedns_ipstr[IP4STRLEN];
extern portno_t  g_fakedns_portno;
extern char      g_fakedns_cidr[64];
extern char      g_fakedns_cache_path[256];
extern skaddr4_t g_fakedns_skaddr;

#endif
