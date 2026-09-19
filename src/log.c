#include "common.h"
#include <stdarg.h>
#include <pthread.h>

typedef struct {
    char text[256];
    int  level;
} log_entry_t;

static log_entry_t     g_ring[LOG_RING_SIZE];
static int             g_total = 0;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static log_sink_fn     g_sink = NULL;
static int             g_console_mode = 0;

void log_set_sink(log_sink_fn fn) {
    pthread_mutex_lock(&g_log_lock);
    g_sink = fn;
    g_console_mode = (fn != NULL);
    pthread_mutex_unlock(&g_log_lock);
}

void log_emit(int level, const char *file, int line, const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);

    int n = 0;
    if (level == 1) {
        n = snprintf(buf, sizeof(buf), "[ERROR] %s:%d ", file ? file : "?", line);
    } else if (level == 0) {
        n = snprintf(buf, sizeof(buf), "[INFO] ");
    }
    if (n < 0) n = 0;
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;
    vsnprintf(buf + n, sizeof(buf) - (size_t)n, fmt, ap);
    va_end(ap);

    log_sink_fn sink;
    int print;
    pthread_mutex_lock(&g_log_lock);
    int idx = g_total % LOG_RING_SIZE;
    snprintf(g_ring[idx].text, sizeof(g_ring[idx].text), "%s", buf);
    g_ring[idx].level = level;
    g_total++;
    sink = g_sink;
    print = !g_console_mode;
    pthread_mutex_unlock(&g_log_lock);

    if (sink) sink();
    else if (print) {
        fprintf(stdout, "%s\n", buf);
        fflush(stdout);
    }
}

int log_total(void) {
    pthread_mutex_lock(&g_log_lock);
    int t = g_total;
    pthread_mutex_unlock(&g_log_lock);
    return t;
}

const char *log_line_at(int index) {
    static char out[256];
    pthread_mutex_lock(&g_log_lock);
    if (index < 0 || index >= g_total) {
        out[0] = '\0';
    } else {
        snprintf(out, sizeof(out), "%s", g_ring[index % LOG_RING_SIZE].text);
    }
    pthread_mutex_unlock(&g_log_lock);
    return out;
}

int log_level_at(int index) {
    pthread_mutex_lock(&g_log_lock);
    int lv = -1;
    if (index >= 0 && index < g_total) lv = g_ring[index % LOG_RING_SIZE].level;
    pthread_mutex_unlock(&g_log_lock);
    return lv;
}
