//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_LOGGING_H_
#define SRC_QTRACE_LOGGING_H_

// Log levels:
// 0 = NONE
// 1 = ERROR
// 2 = WARNING
// 3 = INFO
// 4 = DEBUG
// 5 = TRACE

#define MAX_LOG_LEVEL 2
extern int tcgtaint_loglevel;

// Uncomment to include the program counter (i.e., TB address) in the debug
// logs
#define LOG_PC

#define LOG(level, ...) qtrace_log_(__LINE__, level, __VA_ARGS__)

#if MAX_LOG_LEVEL >= 5
#define TRACE(...) if(tcgtaint_loglevel >=5){ LOG("TRA", __VA_ARGS__); }
#else
#define TRACE(...)
#endif

#if MAX_LOG_LEVEL >= 4
#define DEBUG(...) if(tcgtaint_loglevel >=4){ LOG("DBG", __VA_ARGS__); }
#else
#define DEBUG(...)
#endif

#if MAX_LOG_LEVEL >= 3
#define INFO(...) if(tcgtaint_loglevel >=3){ LOG("INF", __VA_ARGS__); }
#else
#define INFO(...)
#endif

#if MAX_LOG_LEVEL >= 2
#define WARNING(...) if(tcgtaint_loglevel >=2){ LOG("WAR", __VA_ARGS__); }
#else
#define WARNING(...)
#endif

#if MAX_LOG_LEVEL >= 1
#define ERROR(...) if(tcgtaint_loglevel >=1){ LOG("ERR", __VA_ARGS__); }
#else
#define ERROR(...)
#endif

/* Forward declaration */
//class Syscall;

/* Initialize the logging subsystem */
int log_init(const char *filename);

/* Internal logging function. Log macros eventually use this function to write
   log messages. Should not be directly invoked by external modules */
void qtrace_log_(unsigned int l, const char *tag,
                 const char *fmt, ...);

#endif  // SRC_QTRACE_LOGGING_H_
