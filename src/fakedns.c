#define _GNU_SOURCE
#include "fakedns.h"
#include "xxhash.h"
#include "uthash.h"
#include "logutils.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

typedef struct {
    uint32_t ip; /* Key: Network Byte Order */
    char domain[256];
    time_t expire;
    UT_hash_handle hh;
} fakedns_entry_t;

static fakedns_entry_t *g_fakedns_table = NULL;
static pthread_rwlock_t g_fakedns_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static uint32_t g_fakeip_net_host = 0; /* Host byte order */
static uint32_t g_fakeip_mask_host = 0; /* Host byte order */
static uint32_t g_pool_size = 0;
static uint32_t g_pool_used = 0;
static uint32_t g_last_warn_used = 0;  /* for warning log throttling */
static char g_cidr_str[64] = {0};

static const uint32_t FAKEDNS_TTL = 43200; // 12 hours

// Pool usage warning thresholds
#define FAKEDNS_POOL_WARN_THRESHOLD   0.80f  // 80% usage warning
#define FAKEDNS_POOL_CRITICAL_THRESHOLD 0.95f  // 95% usage critical

void fakedns_init(const char *cidr_str) {
    if (!cidr_str) {
        LOGERR("[fakedns_init] cidr_str is NULL");
        exit(1);
    }

    char ip_str[64];
    strncpy(ip_str, cidr_str, sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';
    
    // Store global CIDR for persistence validation
    strncpy(g_cidr_str, cidr_str, sizeof(g_cidr_str) - 1);
    g_cidr_str[sizeof(g_cidr_str) - 1] = '\0';

    char *slash = strchr(ip_str, '/');
    if (!slash) {
        LOGERR("[fakedns_init] invalid cidr format: %s", cidr_str);
        exit(1);
    }
    *slash = '\0';
    char *endptr;
    long prefix_len = strtol(slash + 1, &endptr, 10);

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        LOGERR("[fakedns_init] invalid ip format: %s", ip_str);
        exit(1);
    }

    if (*endptr != '\0' || prefix_len < 0 || prefix_len > 32) {
        LOGERR("[fakedns_init] invalid prefix length: %s", slash + 1);
        exit(1);
    }

    uint32_t ip_host = ntohl(addr.s_addr);
    uint32_t mask_host = (prefix_len == 0) ? 0 : (~0U) << (32 - prefix_len);
    
    g_fakeip_net_host = ip_host & mask_host;
    g_fakeip_mask_host = mask_host;
    g_pool_size = (prefix_len == 32) ? 1 : (1U << (32 - prefix_len));

    LOG_ALWAYS_INF("[fakedns_init] IP range: %s/%ld", ip_str, prefix_len);
    LOG_ALWAYS_INF("[fakedns_init] Pool size: %u addresses (%.1f KB memory)", 
           g_pool_size, (float)(g_pool_size * sizeof(fakedns_entry_t)) / 1024.0f);
    LOG_ALWAYS_INF("[fakedns_init] Warning threshold: %.0f%% (%u entries)", 
           FAKEDNS_POOL_WARN_THRESHOLD * 100.0f, (uint32_t)(g_pool_size * FAKEDNS_POOL_WARN_THRESHOLD));
    LOG_ALWAYS_INF("[fakedns_init] Critical threshold: %.0f%% (%u entries)", 
           FAKEDNS_POOL_CRITICAL_THRESHOLD * 100.0f, (uint32_t)(g_pool_size * FAKEDNS_POOL_CRITICAL_THRESHOLD));
}

uint32_t fakedns_lookup_domain(const char *domain) {
    if (!domain || !g_pool_size) return 0;

    uint64_t hash = XXH3_64bits(domain, strlen(domain));
    uint32_t offset_start = (uint32_t)(hash % g_pool_size);
    uint32_t offset = offset_start;
    time_t now = time(NULL);
    
    // Phase 1: Try read lock first for fast path (cache hit with valid TTL)
    pthread_rwlock_rdlock(&g_fakedns_rwlock);
    
    for (uint32_t i = 0; i < g_pool_size; ++i) {
        uint32_t ip_host = g_fakeip_net_host + offset;
        uint32_t ip_net = htonl(ip_host);
        
        fakedns_entry_t *entry = NULL;
        HASH_FIND_INT(g_fakedns_table, &ip_net, entry);
        
        if (!entry) {
            // Empty slot found, need write lock to insert
            break;
        } else if (strcmp(entry->domain, domain) == 0) {
            // Match found! Check if we need to update TTL
            time_t remaining = entry->expire - now;
            
            // Lazy update: only update if TTL remaining < 30%
            if (remaining > (time_t)(FAKEDNS_TTL * 0.3)) {
                // TTL still healthy, return directly with read lock
                pthread_rwlock_unlock(&g_fakedns_rwlock);
                return ip_net;
            }
            
            // TTL low, need to update - break to acquire write lock
            break;
        } else {
            // Collision, continue probing
            offset = (offset + 1) % g_pool_size;
        }
    }
    
    pthread_rwlock_unlock(&g_fakedns_rwlock);
    
    // Phase 2: Acquire write lock for insert/update
    pthread_rwlock_wrlock(&g_fakedns_rwlock);
    
    // Reset offset for write path
    offset = offset_start;
    
    for (uint32_t i = 0; i < g_pool_size; ++i) {
        uint32_t ip_host = g_fakeip_net_host + offset;
        uint32_t ip_net = htonl(ip_host);
        
        fakedns_entry_t *entry = NULL;
        HASH_FIND_INT(g_fakedns_table, &ip_net, entry);
        
        if (!entry) {
            // Check if pool is full before adding new entry
            if (g_pool_used >= g_pool_size) {
                 pthread_rwlock_unlock(&g_fakedns_rwlock);
                 LOGERR("[fakedns_lookup_domain] pool is full (%u/%u), rejected: %s", g_pool_used, g_pool_size, domain);
                 return 0;
            }

            // Found empty slot, insert new entry
            entry = malloc(sizeof(fakedns_entry_t));
            if (!entry) {
                pthread_rwlock_unlock(&g_fakedns_rwlock);
                LOGERR("[fakedns_lookup_domain] malloc failed for domain: %s", domain);
                return 0;
            }
            entry->ip = ip_net;
            strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
            entry->domain[sizeof(entry->domain) - 1] = '\0';
            entry->expire = now + FAKEDNS_TTL;
            HASH_ADD_INT(g_fakedns_table, ip, entry);
            g_pool_used++;
            
            // Check pool usage and warn if high
            float usage = (float)g_pool_used / (float)g_pool_size;
            if (usage >= FAKEDNS_POOL_CRITICAL_THRESHOLD) {
                LOGWAR("[fakedns] CRITICAL: pool usage %.1f%% (%u/%u), consider expanding pool or restarting", 
                       usage * 100.0f, g_pool_used, g_pool_size);
            } else if (usage >= FAKEDNS_POOL_WARN_THRESHOLD) {
                // Only warn every 5% increase to avoid spam
                if (g_pool_used - g_last_warn_used >= g_pool_size / 20) {
                    LOGWAR("[fakedns] WARNING: pool usage %.1f%% (%u/%u)", 
                           usage * 100.0f, g_pool_used, g_pool_size);
                    g_last_warn_used = g_pool_used;
                }
            }
            
            pthread_rwlock_unlock(&g_fakedns_rwlock);
            return ip_net;
        } else {
            // Slot occupied
            if (strcmp(entry->domain, domain) == 0) {
                // Match confirmed, update TTL
                entry->expire = now + FAKEDNS_TTL;
                pthread_rwlock_unlock(&g_fakedns_rwlock);
                /* LOGINF("[fakedns] hit: %s -> %u.%u.%u.%u", domain, 
                    ip_net & 0xFF, (ip_net >> 8) & 0xFF, (ip_net >> 16) & 0xFF, (ip_net >> 24) & 0xFF); */
                return ip_net;
            } else {
                // Collision
                /* Strategy A: Overwrite if expired */
                if (entry->expire < now) {
                     LOGINF("[fakedns] overwrite expired entry: %s -> %s (IP: %u.%u.%u.%u)",
                            entry->domain, domain,
                            ip_net & 0xFF, (ip_net >> 8) & 0xFF, (ip_net >> 16) & 0xFF, (ip_net >> 24) & 0xFF);
                     
                     // Reset entry for new domain
                     strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
                     entry->domain[sizeof(entry->domain) - 1] = '\0';
                     entry->expire = now + FAKEDNS_TTL;
                     
                     pthread_rwlock_unlock(&g_fakedns_rwlock);
                     return ip_net;
                }
                
                // Still valid, linear probe
                offset = (offset + 1) % g_pool_size;
            }
        }
    }
    
    pthread_rwlock_unlock(&g_fakedns_rwlock);
    LOGERR("[fakedns_lookup_domain] linear probe exhausted for domain: %s", domain);
    return 0;
}

bool fakedns_reverse_lookup(uint32_t ip, char *buffer, size_t buf_len) {
    if (!buffer || buf_len == 0) return false;

    pthread_rwlock_rdlock(&g_fakedns_rwlock);  // Use read lock for lookup
    fakedns_entry_t *entry = NULL;
    HASH_FIND_INT(g_fakedns_table, &ip, entry);
    bool found = false;
    if (entry) {
        strncpy(buffer, entry->domain, buf_len - 1);
        buffer[buf_len - 1] = '\0';
        found = true;
    }
    pthread_rwlock_unlock(&g_fakedns_rwlock);
    return found;
}

/* DNS Packet Layout
 * Header: 12 bytes
 * Question: Name (variable) + Type(2) + Class(2)
 */
 
size_t fakedns_process_query(const uint8_t *query, size_t qlen, uint8_t *buffer, size_t buflen) {
    if (qlen < 12 || buflen < qlen) return 0; // Too short or buffer too small to hold echo
    
    // Header parsing
    // ID (2), Flags (2), QDCOUNT (2), ANCOUNT (2), NSCOUNT (2), ARCOUNT (2)
    uint16_t id = (query[0] << 8) | query[1];
    uint16_t flags = (query[2] << 8) | query[3];
    uint16_t qdcount = (query[4] << 8) | query[5];
    
    // Valid query checks: QR=0, Opcode=0, QDCOUNT=1
    if ((flags & 0xF800) != 0 || qdcount != 1) return 0; // Not a standard query or multiple questions
    
    // Copy ID and set common flags for response (QR=1, RA=1, AA=0, RD from query)
    // RCODE=0 (Success) by default
    uint16_t resp_flags = 0x8180 | (flags & 0x0100); // QR=1, Opcode=0, AA=0, TC=0, RD=from_query, RA=1, Z=0, RCODE=0
    
    // Question parsing
    size_t offset = 12;
    // Walk through QNAME
    char domain[256];
    size_t dom_len = 0;
    while (offset < qlen) {
        uint8_t len = query[offset];
        if (len == 0) {
            offset++;
            break;
        }
        if ((len & 0xC0) == 0xC0) return 0; // Pointers not allowed in Question section usually, and we don't support it in parser
        
        if (offset + 1 + len > qlen) return 0; // Overflow
        
        if (dom_len + len + 1 > sizeof(domain)) return 0; // Too long
        
        if (dom_len > 0) domain[dom_len++] = '.';
        memcpy(domain + dom_len, query + offset + 1, len);
        dom_len += len;
        
        offset += 1 + len;
    }
    
    if (dom_len == 0) return 0; // Empty name
    domain[dom_len] = '\0';
    
    if (offset + 4 > qlen) return 0; // Malformed
    
    uint16_t qtype = (query[offset] << 8) | query[offset + 1];
    uint16_t qclass = (query[offset + 2] << 8) | query[offset + 3];
    
    // We only answer IN class (1)
    if (qclass != 1) {
        resp_flags |= 0x0004; // Not Implemented or similar? Or just Refused?
        // Let's just return NOERROR/NODATA for class mismatch or ignore.
        // But for simplicity, we treat as NODATA.
    }
    
    // Construct buffer
    // Copy Header + Question
    if (offset + 4 > buflen) return 0;
    memcpy(buffer, query, offset + 4);
    
    // Update Header
    buffer[2] = (resp_flags >> 8) & 0xFF;
    buffer[3] = resp_flags & 0xFF;
    // ANCOUNT, NSCOUNT, ARCOUNT = 0 by default
    buffer[6] = 0; buffer[7] = 0;
    buffer[8] = 0; buffer[9] = 0;
    buffer[10] = 0; buffer[11] = 0;
    
    size_t resp_len = offset + 4;
    
    if (qtype == 1) { /* A Record */
        uint32_t fakeip = fakedns_lookup_domain(domain);
        if (fakeip) {
            // Add Answer
            // Ptr to name (0xC00C - Offset 12)
            if (resp_len + 16 > buflen) return 0; // 2(Ptr) + 2(Type) + 2(Class) + 4(TTL) + 2(Len) + 4(IP)
            
            buffer[resp_len++] = 0xC0;
            buffer[resp_len++] = 0x0C;
            
            buffer[resp_len++] = 0x00; buffer[resp_len++] = 0x01; // Type A
            buffer[resp_len++] = 0x00; buffer[resp_len++] = 0x01; // Class IN
            /* TTL */
            uint32_t ttl_n = htonl(FAKEDNS_TTL);
            memcpy(buffer + resp_len, &ttl_n, 4);
            resp_len += 4;
            /* RDLENGTH = 4 */
            buffer[resp_len++] = 0x00; buffer[resp_len++] = 0x04;
            /* RDATA */
            memcpy(buffer + resp_len, &fakeip, 4);
            resp_len += 4;
            
            // Set ANCOUNT = 1
            buffer[7] = 1;
            
            LOGINF("[fakedns] query: A %s -> %u.%u.%u.%u", domain, 
                fakeip & 0xFF, (fakeip >> 8) & 0xFF, (fakeip >> 16) & 0xFF, (fakeip >> 24) & 0xFF);
        }
    } else if (qtype == 28) { /* AAAA Record */
        // Return NOERROR with 0 Answers (Handling dual-stack fallback)
        LOGINF("[fakedns] query: AAAA %s -> NODATA", domain);
    } else {
        // Other types -> NODATA
    }
    
    return resp_len;
}

static const uint32_t FAKEDNS_MAGIC = 0x464E5344; // "DNSF" Little Endian -> "FNSD"
static const uint32_t FAKEDNS_VERSION = 2;

void fakedns_save(const char *path) {
    if (!path || !g_fakedns_table) return;

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        LOGERR("[fakedns_save] failed to open %s: %s", path, strerror(errno));
        return;
    }

    pthread_rwlock_rdlock(&g_fakedns_rwlock);  // Use read lock for saving
    
    // Count valid entries
    uint32_t count = 0;

    fakedns_entry_t *entry, *tmp;
    HASH_ITER(hh, g_fakedns_table, entry, tmp) {
        count++;
    }

    // Write Header
    if (fwrite(&FAKEDNS_MAGIC, 4, 1, fp) != 1 ||
        fwrite(&FAKEDNS_VERSION, 4, 1, fp) != 1 ||
        fwrite(&count, 4, 1, fp) != 1) {
        LOGERR("[fakedns_save] failed to write header to %s", path);
        pthread_rwlock_unlock(&g_fakedns_rwlock);
        fclose(fp);
        return;
    }

    // Version 2: Write CIDR
    uint16_t cidr_len = strlen(g_cidr_str);
    if (fwrite(&cidr_len, 2, 1, fp) != 1 ||
        fwrite(g_cidr_str, 1, cidr_len, fp) != cidr_len) {
        LOGERR("[fakedns_save] failed to write CIDR to %s", path);
        pthread_rwlock_unlock(&g_fakedns_rwlock);
        fclose(fp);
        return;
    }

    // Write Entries
    HASH_ITER(hh, g_fakedns_table, entry, tmp) {
        uint16_t dlen = strlen(entry->domain);
        if (fwrite(&entry->ip, 4, 1, fp) != 1 ||
            fwrite(&entry->expire, 8, 1, fp) != 1 ||
            fwrite(&dlen, 2, 1, fp) != 1 ||
            fwrite(entry->domain, 1, dlen, fp) != dlen) {
            LOGERR("[fakedns_save] failed to write entry to %s", path);
            break;
        }
    }

    pthread_rwlock_unlock(&g_fakedns_rwlock);
    fclose(fp);
    LOG_ALWAYS_INF("[fakedns_save] saved %u entries to %s", count, path);
}

void fakedns_load(const char *path) {
    if (!path) return;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        if (errno != ENOENT) {
            LOGERR("[fakedns_load] failed to open %s: %s", path, strerror(errno));
        }
        return;
    }

    uint32_t magic, version, count;
    if (fread(&magic, 4, 1, fp) != 1 || fread(&version, 4, 1, fp) != 1 || fread(&count, 4, 1, fp) != 1) {
        LOGERR("[fakedns_load] header read error");
        fclose(fp);
        return;
    }

    if (magic != FAKEDNS_MAGIC) {
        LOGERR("[fakedns_load] invalid magic: %08x", magic);
        fclose(fp);
        return;
    }
    if (version != FAKEDNS_VERSION) {
        LOGERR("[fakedns_load] version mismatch: file %u, current %u", version, FAKEDNS_VERSION);
        fclose(fp);
        return;
    }

    // Version 2: Check CIDR
    if (version >= 2) {
        uint16_t cidr_len;
        if (fread(&cidr_len, 2, 1, fp) != 1) {
            LOGERR("[fakedns_load] cidr len read error");
            fclose(fp);
            return;
        }
        if (cidr_len >= 64) {
             LOGERR("[fakedns_load] cidr len too long: %u", cidr_len);
             fclose(fp);
             return;
        }
        char file_cidr[64];
        if (fread(file_cidr, 1, cidr_len, fp) != cidr_len) {
            LOGERR("[fakedns_load] cidr read error");
            fclose(fp);
            return;
        }
        file_cidr[cidr_len] = '\0';
        
        if (strcmp(file_cidr, g_cidr_str) != 0) {
            LOGERR("[fakedns_load] CIDR mismatch. File: %s, Current: %s. Ignoring saved data.", file_cidr, g_cidr_str);
            fclose(fp);
            return;
        }
    }

    pthread_rwlock_wrlock(&g_fakedns_rwlock);  // Use write lock for loading
    
    time_t now = time(NULL);
    uint32_t loaded = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t ip;
        uint64_t expire64; // Read as 64-bit
        uint16_t dlen;
        
        if (fread(&ip, 4, 1, fp) != 1 || fread(&expire64, 8, 1, fp) != 1 || fread(&dlen, 2, 1, fp) != 1) {
            LOGERR("[fakedns_load] entry read error at %u", i);
            break;
        }

        // Validate IP in range
        // g_fakeip_net_host is host byte order, ip is network byte order
        uint32_t ip_host = ntohl(ip);
        if ((ip_host & g_fakeip_mask_host) != g_fakeip_net_host) {
            fseek(fp, dlen, SEEK_CUR); // Skip domain
            // Even if CIDR matches string-wise, let's be double safe
            continue;
        }

        if (dlen >= 256) {
             LOGERR("[fakedns_load] domain too long: %u", dlen);
             fseek(fp, dlen, SEEK_CUR);
             continue;
        }

        char domain[256];
        if (fread(domain, 1, dlen, fp) != dlen) {
             LOGERR("[fakedns_load] domain read error at %u", i);
             break;
        }
        domain[dlen] = '\0';

        // Refresh TTL on load
        time_t expire = now + FAKEDNS_TTL;

        // Add to hash
         fakedns_entry_t *entry = NULL;
         HASH_FIND_INT(g_fakedns_table, &ip, entry);
         if (!entry) {
             entry = malloc(sizeof(fakedns_entry_t));
             if (!entry) {
                 LOGERR("[fakedns_load] malloc failed for domain: %s", domain);
                 continue;
             }
             entry->ip = ip;
             strncpy(entry->domain, domain, sizeof(entry->domain));
             entry->expire = expire;
             HASH_ADD_INT(g_fakedns_table, ip, entry);
             g_pool_used++;
             loaded++;
         } else {
             // Overwrite if exists? Or ignore?
             // Since we just started, likely collision or reload. Update logic.
             strncpy(entry->domain, domain, sizeof(entry->domain));
             entry->expire = expire;
         }
    }

    pthread_rwlock_unlock(&g_fakedns_rwlock);
    fclose(fp);
    LOG_ALWAYS_INF("[fakedns_load] loaded %u/%u entries from %s", loaded, count, path);
}
