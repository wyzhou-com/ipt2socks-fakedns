#define _GNU_SOURCE
#include "logutils.h"
#include <stdarg.h>

static char g_log_time_str[20] = "0000-00-00 00:00:00";
static atomic_long g_log_time_epoch = 0;

static inline void update_log_time(void) {
    time_t now = time(NULL);
    /* Only update when seconds change (avoid repeated conversion) */
    if (now != atomic_load_explicit(&g_log_time_epoch, memory_order_relaxed)) {
        atomic_store_explicit(&g_log_time_epoch, now, memory_order_relaxed);
        struct tm tm;
        localtime_r(&now, &tm);
        snprintf(g_log_time_str, sizeof(g_log_time_str),
                 "%04d-%02d-%02d %02d:%02d:%02d",
                 tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                 tm.tm_hour, tm.tm_min, tm.tm_sec);
    }
}

void log_print(log_level_t level, const char *fmt, ...) {
    update_log_time();
    
    const char *color = "";
    const char *label = "";
    
    switch (level) {
        case LOG_LEVEL_INF:
        case LOG_LEVEL_ALWAYS_INF:
            color = "\e[1;32m"; // Green
            label = "INF";
            break;
        case LOG_LEVEL_ERR:
            color = "\e[1;35m"; // Magenta
            label = "ERR";
            break;
        case LOG_LEVEL_WAR:
            color = "\e[1;33m"; // Yellow
            label = "WAR";
            break;
    }

    printf("%s%s %s:\e[0m ", color, g_log_time_str, label);

    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    printf("\n");
}
