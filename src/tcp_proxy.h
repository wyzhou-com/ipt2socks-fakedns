#ifndef IPT2SOCKS_TCP_PROXY_H
#define IPT2SOCKS_TCP_PROXY_H

#include <stdint.h>
#include "../libev/ev.h"

#define TCP_SPLICE_MAXLEN 65535 /* uint16_t: 0~65535 */

typedef struct tcp_context_t {
    evio_t   client_watcher;   // .data: socks5 mesg
    evio_t   socks5_watcher;   // .data: socks5 mesg
    int      client_pipefd[2]; // client pipe buffer
    int      socks5_pipefd[2]; // socks5 pipe buffer
    uint16_t client_length;    // nrecv/nsend, npipe
    uint16_t socks5_length;    // nrecv/nsend, npipe
    uint8_t  handshake_buf[600]; // Buffer for handshake messages
    struct tcp_context_t *prev;  // Doubly linked list for cleanup
    struct tcp_context_t *next;
} tcp_context_t;

void tcp_tproxy_accept_cb(evloop_t *evloop, evio_t *watcher, int revents);
void tcp_proxy_close_all_sessions(evloop_t *evloop);

#endif
