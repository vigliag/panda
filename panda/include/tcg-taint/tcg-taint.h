#pragma once
#include <stdbool.h>

/* External variable that indicates whether taint propagation is currently
   enabled or not */
extern bool qtrace_taint_instrumentation_enabled;

/* "true" when generating instrumentation micro-ops. This flag is necessary to
    avoid instrumentation of our own code (and thus possible endless loops) */
extern bool qtrace_in_instrumentation;

/** "true" when tcg is generating sse instructions
    we use it to only instrument non-instrumentation micro ops
    (ie. we don't want to instrument panda's own instrumentation)*/
extern bool qtrace_tcg_is_generating_sse;

#ifdef __cplusplus
extern "C" {
#endif

void tcg_taint_instrumentation_init(void);
void tcg_taint_instrumentation_enable(void);
void tcg_taint_instrumentation_disable(void);

#ifdef __cplusplus
}
#endif
