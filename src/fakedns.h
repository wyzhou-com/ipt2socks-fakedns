#ifndef IPT2SOCKS_FAKEDNS_H
#define IPT2SOCKS_FAKEDNS_H

#include <stdint.h>
#include <stddef.h>

void fakedns_init(const char *cidr_str);
uint32_t fakedns_lookup_domain(const char *domain);
#include <stdbool.h>
bool fakedns_reverse_lookup(uint32_t ip, char *buffer, size_t buf_len);

size_t fakedns_process_query(const uint8_t *query, size_t qlen, uint8_t *buffer, size_t buflen);

void fakedns_save(const char *path);
void fakedns_load(const char *path);

void fakedns_get_stats(uint32_t *pool_size, uint32_t *pool_used, float *usage_percent);

#endif
