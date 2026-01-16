#ifndef IPT2SOCKS_UDP_PROXY_H
#define IPT2SOCKS_UDP_PROXY_H

#include <stdint.h>
#include <stddef.h>
#include "../libev/ev.h"

/* Memory pool configuration */
#define MEMPOOL_BLOCK_SIZE    2048
#define MEMPOOL_INITIAL_SIZE  256

/* UDP Queue */
#define UDP_QUEUE_MAX_DEPTH 64

/* Maximum SOCKS5 UDP header size */
#define MAX_DOMAIN_LEN         255
#define MAX_SOCKS5_UDP_HEADER  262

typedef struct udp_packet_node {
    struct udp_packet_node *next;
    size_t len;
    uint8_t data[];
} udp_packet_node_t;

typedef struct {
    udp_packet_node_t *head;
    udp_packet_node_t *tail;
    size_t count;
} udp_packet_queue_t;

void udp_tproxy_recvmsg_cb(evloop_t *evloop, evio_t *watcher, int revents);
void udp_dns_recv_cb(evloop_t *evloop, evio_t *watcher, int revents);

#endif
