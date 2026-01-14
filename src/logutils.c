#define _GNU_SOURCE
#include "logutils.h"

char g_log_time_str[20] = "0000-00-00 00:00:00";
atomic_long g_log_time_epoch = 0;
