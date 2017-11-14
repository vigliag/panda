#pragma once
#include "taintengine.hpp"

struct TCGTaintContext {
    TaintEngine *taint_engine = nullptr;
};

extern TCGTaintContext tcgtaint_ctx;
extern bool taint_is_user_enabled;
extern bool taint_in_kernel_space;
