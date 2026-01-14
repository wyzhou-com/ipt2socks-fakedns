#ifndef IPT2SOCKS_LOGUTILS_H
#define IPT2SOCKS_LOGUTILS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <stdatomic.h>

extern bool g_verbose;
#define IF_VERBOSE if (g_verbose)

/* Cached time string (thread-safe) */
extern char g_log_time_str[20];  /* "YYYY-MM-DD HH:MM:SS" */
extern atomic_long g_log_time_epoch;

static inline void update_log_time(void) {
    time_t now = time(NULL);
    /* Only update when seconds change (avoid repeated conversion) */
    if (now != atomic_load(&g_log_time_epoch)) {
        atomic_store(&g_log_time_epoch, now);
        struct tm tm;
        localtime_r(&now, &tm);
        snprintf(g_log_time_str, sizeof(g_log_time_str),
                 "%04d-%02d-%02d %02d:%02d:%02d",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec);
    }
}

#define LOG_ALWAYS_INF(fmt, ...)                                 \
    do {                                                         \
        update_log_time();                                       \
        printf("\e[1;32m%s INF:\e[0m " fmt "\n",                 \
               g_log_time_str, ##__VA_ARGS__);                   \
    } while (0)

#define LOGINF(fmt, ...)           \
    do {                           \
        if (g_verbose) {           \
             LOG_ALWAYS_INF(fmt, ##__VA_ARGS__); \
        }                          \
    } while (0)

#define LOGERR(fmt, ...)                                         \
    do {                                                         \
        update_log_time();                                       \
        printf("\e[1;35m%s ERR:\e[0m " fmt "\n",                 \
               g_log_time_str, ##__VA_ARGS__);                   \
    } while (0)

#define LOGWAR(fmt, ...)                                         \
    do {                                                         \
        update_log_time();                                       \
        printf("\e[1;33m%s WAR:\e[0m " fmt "\n",                 \
               g_log_time_str, ##__VA_ARGS__);                   \
    } while (0)

#endif
