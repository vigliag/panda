//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include <cstring>
#include <cstdlib>
#include <cassert>

#include "panda/plugin.h"
#include "logging.hpp"
#include "taintengine.hpp"
#include "tcgtaint.hpp"
#include "notify_taint.hpp"

static inline bool physical_address_is_valid(hwaddr phyaddr){
#ifndef CONFIG_USER_ONLY
  return phyaddr == static_cast<hwaddr>(-1);
#else
  return false;
#endif
}

static inline hwaddr virt_to_phys(target_ulong addr, unsigned int size){
    (void) size;
    return panda_virt_to_phys(current_cpu, addr);
}

namespace qtrace {

    void notify_taint_moveM2R(target_ulong addr, int size,
                              bool istmp, target_ulong reg) {
      hwaddr phyaddr = virt_to_phys(addr, size);
      if (physical_address_is_valid(phyaddr)) {
        WARNING("Invalid address (VA: %.8x, PHY: %.8x)", addr, phyaddr);
        return;
      }
      tcgtaint_ctx.taint_engine->moveM2R(phyaddr, size, istmp, reg);
    }

    void notify_taint_moveR2M(bool istmp, target_ulong reg,
                              target_ulong addr, int size) {
      hwaddr phyaddr = virt_to_phys(addr, size);
      if (physical_address_is_valid(phyaddr)) {
        WARNING("Invalid address (VA: %.8x, PHY: %.8x)", addr, phyaddr);
        return;
      }
      tcgtaint_ctx.taint_engine->moveR2M(istmp, reg, phyaddr, size);
    }

    void notify_taint_moveR2R(bool srctmp, target_ulong src,
                              bool dsttmp, target_ulong dst) {
      tcgtaint_ctx.taint_engine->moveR2R(srctmp, src, dsttmp, dst);
    }

    void notify_taint_moveR2R_offset(bool srctmp, target_ulong src,
                                     unsigned int srcoff,
                                     bool dsttmp, target_ulong dst,
                                     unsigned int dstoff,
                                     int size) {
      tcgtaint_ctx.taint_engine->moveR2R(srctmp, src, srcoff,
                                        dsttmp, dst, dstoff,
                                        size);
    }

    void notify_taint_clearR(bool istmp, target_ulong reg) {
      tcgtaint_ctx.taint_engine->clearRegister(istmp, reg);
    }

    void notify_taint_clearM(target_ulong addr, int size) {
      hwaddr phyaddr = virt_to_phys(addr, size);
      if (physical_address_is_valid(phyaddr)) {
        return;
      }

      tcgtaint_ctx.taint_engine->clearMemory(phyaddr, size);
    }

    void notify_taint_endtb() {
      tcgtaint_ctx.taint_engine->clearTempRegisters();
    }

    void notify_taint_regalloc(target_ulong reg, const char *name) {
      printf("REGALLOC %d %s", reg, name);
      if(reg >= 16){
          printf(" ignoring segment register");
      } else {
          tcgtaint_ctx.taint_engine->setRegisterName(reg, name);
      }
      printf("\n");
    }

    void notify_taint_combineR2R(bool srctmp, target_ulong src,
                                 bool dsttmp, target_ulong dst) {
      tcgtaint_ctx.taint_engine->combineR2R(srctmp, src, dsttmp, dst);
    }

    void notify_taint_assert(target_ulong reg, bool istrue) {
      WARNING("Asserting register %s(%d) IS%s tainted",
              tcgtaint_ctx.taint_engine->getRegisterName(reg), reg,
              istrue ? "" : " NOT");

      bool b = tcgtaint_ctx.taint_engine->isTaintedRegister(false, reg, 0);
      assert(istrue ? b : !b);
    }

    //void notify_taint_set_state(bool state) {
    //  tcgtaint_ctx.taint_engine->setUserEnabled(state);
    //}

    //bool notify_taint_get_state(void) {
    //  return tcgtaint_ctx.taint_engine->isUserEnabled();
    //}
}
