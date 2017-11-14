//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "logging.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <panda/plugin.h>

static FILE *logfile;

static uint32_t get_current_pc() { return panda_current_pc(current_cpu); }

int log_init(const char *filename) {
    if (!filename) {
        return 0;
    }

    // Initialize the log file
    logfile = fopen(filename, "w+");
    if (!logfile) {
        ERROR("Cannot open log file for writing");
        return -1;
    }

    return 0;
}

void qtrace_log_(unsigned int l, const char *tag, const char *fmt, ...) {
    va_list ap;
    char tmp[1024];

    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    char pc[32];

#if defined(LOG_PC)
    uint32_t pcval = get_current_pc();
    if (pcval) {
        snprintf(pc, sizeof(pc), "@%.8x ", pcval);
    } else {
        snprintf(pc, sizeof(pc), "@_unknown ");
    }
#else
    pc[0] = '\0';
#endif

    fprintf(logfile ? logfile : stderr, "_taint %s[:%d] [%s] %s\n", pc, l, tag,
            tmp);
}
