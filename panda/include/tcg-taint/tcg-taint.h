#pragma once

/* External variable that indicates whether taint propagation is currently
   enabled or not */
extern bool qtrace_taint_enabled;
   
/* "true" when generating instrumentation micro-ops. This flag is necessary to
    avoid instrumentation of our own code (and thus possible endless loops) */
extern bool qtrace_instrument;

void tcg_taint_enable(void);