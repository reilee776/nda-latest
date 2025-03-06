#include "../nd_nix_nfm_common.h"
#include <linux/string.h>
#include "nd_nix_util_str.h"


//void nd_add_log (const char *msg, int level, char* filename, int line);
void nd_add_log ( int level, char* filename, int line, const char *fmt, ...);

ssize_t nd_get_logs (char __user *buf , size_t count);

void set_debug_log_enabled(bool enabled);

void set_warn_log_enabled(bool enabled);

void set_trace_log_enabled(bool enabled);

void set_info_log_enabled(bool enabled);

void set_error_log_enabled(bool enabled);

bool get_debug_log_enabled(void);

bool get_warn_log_enabled(void);

bool get_trace_log_enabled(void);

bool get_info_log_enabled(void);

bool get_error_log_enabled(void);
