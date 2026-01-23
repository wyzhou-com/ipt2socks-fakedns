#include "ctx.h"

bool     g_verbose  = false;
uint16_t g_options  = OPT_ENABLE_TCP | OPT_ENABLE_UDP | OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6;
uint8_t  g_nthreads = 1;

char      g_bind_ipstr4[IP4STRLEN] = IP4STR_LOOPBACK;
char      g_bind_ipstr6[IP6STRLEN] = IP6STR_LOOPBACK;
portno_t  g_bind_portno            = 60080;
skaddr4_t g_bind_skaddr4           = {0};
skaddr6_t g_bind_skaddr6           = {0};

char      g_server_ipstr[IP6STRLEN] = "127.0.0.1";
portno_t  g_server_portno           = 1080;
skaddr6_t g_server_skaddr           = {0};

uint8_t g_tcp_syncnt_max = 0; // 0: use default syncnt

uint16_t g_udp_idletimeout_sec                           = 60;
__thread udp_socks5ctx_t *g_udp_socks5ctx_table          = NULL;
__thread udp_socks5ctx_t *g_udp_fork_table               = NULL; // Fork table
__thread udp_tproxyctx_t *g_udp_tproxyctx_table          = NULL;
__thread char    g_udp_batch_buffer[UDP_BATCH_SIZE][UDP_DATAGRAM_MAXSIZ];
__thread memory_pool_t *g_udp_packet_pool                = NULL;
__thread memory_pool_t *g_udp_context_pool               = NULL;
__thread memory_pool_t *g_tcp_context_pool               = NULL;
__thread void          *g_tcp_session_head               = NULL;

char      g_fakedns_ipstr[IP4STRLEN] = "127.0.0.1";
portno_t  g_fakedns_portno           = 5353;
char      g_fakedns_cidr[64]         = "198.18.0.0/15";
char      g_fakedns_cache_path[256]  = {0};
skaddr4_t g_fakedns_skaddr           = {0};
