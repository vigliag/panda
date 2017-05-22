#ifndef PANDALOGGING_HPP
#define PANDALOGGING_HPP

#include "callmemaccesstracker.hpp"

void logSysFnCall(uint64_t callid, uint64_t entrypoint, CallMemAccessTracker& cmt, FILE* outfile);

#endif // PANDALOGGING_HPP
