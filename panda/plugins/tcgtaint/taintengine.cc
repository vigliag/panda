//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include <algorithm>
#include <assert.h>

#include "shadow.hpp"
#include "taintengine.hpp"
#include "tcg-taint/tcg-taint.h"

#include "logging.hpp"

#define REGCHR(x) ((x) ? 't' : 'c')
#define REGNAME(obj)                                                           \
    ((obj)->getName().length() > 0 ? (obj)->getName().c_str() : "noname")
#define REGTAINT(obj) ((obj)->isTainted() ? 'T' : 'C')

void TaintEngine::setRegisterName(target_ulong regno, const char *name) {
    ShadowRegister *reg = getRegister(RegisterKind::global, regno);
    assert(reg);
    assert(reg->getName().length() == 0);
    reg->setName(name);
}

const char *TaintEngine::getRegisterName(target_ulong regno) {
    ShadowRegister *reg = getRegister(RegisterKind::global, regno);
    return REGNAME(reg);
}

bool TaintEngine::getRegisterIdByName(const char *name,
                                      target_ulong &regno) const {
    for (int i = 0; i < NUM_CPU_REGS; i++) {
        if (cpuregs_[i].getName() == name) {
            regno = i;
            return true;
        }
    }
    return false;
}

ShadowRegister *TaintEngine::getRegister(RegisterKind istmp, target_ulong reg) {
    switch (istmp) {
    case RegisterKind::temporary:
        assert(reg < NUM_TMP_REGS);
        return &tmpregs_[reg];
    case RegisterKind::global:
        assert(reg < NUM_CPU_REGS);
        return &cpuregs_[reg];
    }
    return nullptr;
}

void TaintEngine::setTaintedRegister(int label, RegisterKind istmp,
                                     target_ulong regno) {
    ShadowRegister *reg = getRegister(istmp, regno);

    TRACE("Tainting register R%c(%.2x %s) with lbl=%d", REGCHR(istmp), regno,
          REGNAME(reg), label);

    reg->set(label);
    _updateRegisterCache(istmp, regno, true);
}

bool TaintEngine::isTaintedRegister(RegisterKind tmp, target_ulong regno,
                                    unsigned int offset, int size) {
    // Try the fast path first
    if (!isTaintedRegister(tmp, regno)) {
        return false;
    }

    // Fallback on the slow path
    const ShadowRegister *reg = getRegister(tmp, regno);

    if (size == -1) {
        size = reg->getSize();
    }

    for (unsigned int i = offset; i < offset + size; i++) {
        if (reg->isTaintedByte(i)) {
            return true;
        }
    }
    return false;
}

void TaintEngine::setTaintedMemory(int label, target_ulong addr,
                                   unsigned int size) {
    TRACE("Tainting %d bytes at %.8x with lbl=%d", size, addr, label);
    for (unsigned int i = 0; i < size; i++) {
        mem_.addLabel(addr + i, label);
    }
}

bool TaintEngine::isTaintedMemory(target_ulong addr, unsigned int size) const {
    for (target_ulong a = addr; a < addr + size; a++) {
        if (mem_.isTaintedAddress(a)) {
            return true;
        }
    }
    return false;
}

void TaintEngine::clearRegister(RegisterKind tmp, target_ulong regno) {
    if (!isTaintedRegister(tmp, regno)) {
        // Nothing to do
        return;
    }

    ShadowRegister *reg = getRegister(tmp, regno);
    TRACE("Clearing R%c(%.2x %s)", REGCHR(tmp), regno, REGNAME(reg));
    reg->clear();
    _updateRegisterCache(tmp, regno, false);
}

void TaintEngine::clearMemory(target_ulong addr, int size) {
    mem_.clear(addr, size);
}

void TaintEngine::moveR2R(RegisterKind srctmp, target_ulong src,
                          RegisterKind dsttmp, target_ulong dst) {
    if (!isTaintedRegister(srctmp, src) && !isTaintedRegister(dsttmp, dst)) {
        // Nothing to do
        return;
    }

    ShadowRegister *dstreg = getRegister(dsttmp, dst);
    ShadowRegister *srcreg = getRegister(srctmp, src);

    TRACE("Taint moving R%c(%.2x %s %c) -> R%c(%.2x %s %c) lbl=%d", REGCHR(srctmp),
          src, REGNAME(srcreg), REGTAINT(srcreg), REGCHR(dsttmp), dst,
          REGNAME(dstreg), REGTAINT(dstreg), srcreg->firstLabel());

    dstreg->set(*srcreg);
    _updateRegisterCache(dsttmp, dst, dstreg->isTainted());
}

void TaintEngine::moveR2R(RegisterKind srctmp, target_ulong src,
                          unsigned int srcoff, RegisterKind dsttmp,
                          target_ulong dst, unsigned int dstoff, int size) {
    assert(size <= 8);

    if (!isTaintedRegister(srctmp, src) && !isTaintedRegister(dsttmp, dst)) {
        // Nothing to do
        return;
    }

    ShadowRegister *dstreg = getRegister(dsttmp, dst);
    ShadowRegister *srcreg = getRegister(srctmp, src);

    for (unsigned i = 0; i < size; i++) {
        TRACE("Taint moving 1 byte R%c(%.2x %s %c @%d) -> R%c(%.2x %s %c @%d), lbl=%d",
              REGCHR(srctmp), src, REGNAME(srcreg), REGTAINT(srcreg),
              srcoff + i, REGCHR(dsttmp), dst, REGNAME(dstreg),
              REGTAINT(dstreg), dstoff + i, srcreg->firstLabel());
        dstreg->set(srcreg->getTaintLocation(srcoff + i), dstoff + i);
    }

    _updateRegisterCache(dsttmp, dst, dstreg->isTainted());
}

void TaintEngine::combineR2R(RegisterKind srctmp, target_ulong src,
                             RegisterKind dsttmp, target_ulong dst) {
    if (!isTaintedRegister(srctmp, src)) {
        // Nothing to do
        return;
    }

    ShadowRegister *dstreg = getRegister(dsttmp, dst);
    ShadowRegister *srcreg = getRegister(srctmp, src);

    TRACE("Taint combining R%c(%.2x %s %c) -> R%c(%.2x %s %c), lbl=%d", REGCHR(srctmp),
          src, REGNAME(srcreg), REGTAINT(srcreg), REGCHR(dsttmp), dst,
          REGNAME(dstreg), REGTAINT(dstreg), srcreg->firstLabel());

    dstreg->combine(*srcreg);
    _updateRegisterCache(dsttmp, dst, dstreg->isTainted());
}

void TaintEngine::moveM2R(target_ulong addr, unsigned size, RegisterKind regtmp,
                          target_ulong reg) {
    assert(size <= 8);
    ShadowRegister *regobj = getRegister(regtmp, reg);

    TRACE("M2R M(%.8x) -> R%c(%.2x %s), size=%d", addr, REGCHR(regtmp), reg,
          REGNAME(regobj), size);

    for (unsigned i = 0; i < std::min(size, regobj->getSize()); i++) {
        if (!mem_.isTaintedAddress(addr + i)) {
            if (regobj->isTaintedByte(i)) {
                TRACE("Clearing M(%.8x) -> R%c(%.2x %s), off=%d", addr + i,
                      REGCHR(regtmp), reg, REGNAME(regobj), i);
                regobj->clear(i, 1);
            }
        } else {
            TRACE("Taint moving M(%.8x) -> R%c(%.2x %s), lbl=%d, off=%d",
                  addr + i, REGCHR(regtmp), reg, REGNAME(regobj),
                  *mem_.getTaintLocation(addr + i)->getLabels().begin(), i);
            regobj->set(mem_.getTaintLocation(addr + i), i);
        }
    }
    _updateRegisterCache(regtmp, reg, regobj->isTainted());
}

void TaintEngine::moveMicroM2R(target_ulong addr, unsigned size,
                               RegisterKind regtmp, target_ulong reg) {
    assert(size <= 8);
    ShadowRegister *regobj = getRegister(regtmp, reg);

    for (unsigned i = 0; i < std::min(size, regobj->getSize()); i++) {
        if (!cpuarchstate_.isTaintedAddress(addr + i)) {
            if (regobj->isTaintedByte(i)) {
                TRACE("Clearing MicroM(%.8x) -> R%c(%.2x %s), off=%d", addr + i,
                      REGCHR(regtmp), reg, REGNAME(regobj), i);
                regobj->clear(i, 1);
            }
        } else {
            TRACE(
                "Taint moving MicroM(%.8x) -> R%c(%.2x %s), lbl=%d, off=%d",
                addr + i, REGCHR(regtmp), reg, REGNAME(regobj),
                *cpuarchstate_.getTaintLocation(addr + i)->getLabels().begin(),
                i);
            regobj->set(cpuarchstate_.getTaintLocation(addr + i), i);
        }
    }
    _updateRegisterCache(regtmp, reg, regobj->isTainted());
}

void TaintEngine::combineM2R(target_ulong addr, unsigned size,
                             RegisterKind regtmp, target_ulong reg) {
    assert(size <= 8);

    ShadowRegister *regobj = getRegister(regtmp, reg);
    for (unsigned i = 0; i < std::min(size, regobj->getSize()); i++) {
        if (mem_.isTaintedAddress(addr + i)) {
            regobj->combine(mem_.getTaintLocation(addr + i), i);
        }
    }
    _updateRegisterCache(regtmp, reg, regobj->isTainted());
}

void TaintEngine::moveR2M(RegisterKind regtmp, target_ulong reg,
                          target_ulong addr, unsigned size) {

    // NOTE: this can get passed 8bytes temporary registers from st_i64
    assert(size <= 8);

    ShadowRegister *regobj = getRegister(regtmp, reg);

    TRACE("R2M R%c(%.2x %s) -> M(%.8x), lb=%d size=%d", REGCHR(regtmp),
          reg, REGNAME(regobj), addr, regobj->firstLabel(), size);

    for (unsigned i = 0; i < std::min(size, regobj->getSize()); i++) {
        if (!regobj->isTaintedByte(i)) {
            if (mem_.isTaintedAddress(addr + i)) {
                // Source is not tainted but destination is: clear
                TRACE("Clearing R%c(%.2x %s) -> M(%.8x)", REGCHR(regtmp), reg,
                      REGNAME(regobj), addr + i);
                mem_.clear(addr + i);
            }
        } else {
            // Source is tainted: move
            TRACE("Taint moving R%c(%.2x %s) -> M(%.8x), lb=%d", REGCHR(regtmp),
                  reg, REGNAME(regobj), addr + i,
                  *regobj->getTaintLocation(i)->getLabels().begin());
            mem_.set(regobj->getTaintLocation(i), addr + i);
        }
    }
}

void TaintEngine::moveR2MicroM(RegisterKind regtmp, target_ulong reg,
                               target_ulong addr, unsigned size) {
    TRACE("moveR2MicroM reg=%d addr=%x size=%d", reg, addr, size);
    // NOTE: this can get passed 8bytes temporary registers from st_i64
    assert(size <= 8);

    ShadowRegister *regobj = getRegister(regtmp, reg);
    for (unsigned i = 0; i < std::min(size, regobj->getSize()); i++) {
        if (!regobj->isTaintedByte(i)) {
            if (cpuarchstate_.isTaintedAddress(addr + i)) {
                // Source is not tainted but destination is: clear
                TRACE("Clearing R%c(%.2x %s) -> MicroM(%.8x)", REGCHR(regtmp),
                      reg, REGNAME(regobj), addr + i);
                cpuarchstate_.clear(addr + i);
            }
        } else {
            // Source is tainted: move
            TRACE("Taint moving R%c(%.2x %s) -> MicroM(%.8x), lb=%d",
                  REGCHR(regtmp), reg, REGNAME(regobj), addr + i,
                  *regobj->getTaintLocation(i)->getLabels().begin());
            cpuarchstate_.set(regobj->getTaintLocation(i), addr + i);
        }
    }
}

void TaintEngine::combineR2M(RegisterKind regtmp, target_ulong reg,
                             target_ulong addr, unsigned size) {
    assert(size <= 8);
    ShadowRegister *regobj = getRegister(regtmp, reg);

    for (unsigned i = 0; i < std::min(size, regobj->getSize()); i++) {
        if (regobj->isTaintedByte(i)) {
            mem_.combine(regobj->getTaintLocation(i), addr + i);
        }
    }
}

void TaintEngine::clearTempRegisters() {
    for (int regno = 0; regno < NUM_TMP_REGS; regno++) {
        if (regcache_tmp_[regno]) {
            tmpregs_[regno].clear();
        }
    }
    regcache_tmp_.reset();
}

void TaintEngine::copyMemoryLabels(std::set<int> &labels, target_ulong addr,
                                   unsigned int size) const {
    for (target_ulong a = addr; a < addr + size; a++) {
        if (mem_.isTaintedAddress(a)) {
            TaintLocation *loc = mem_.getTaintLocation(a);
            loc->copy(labels);
        }
    }
}

// added to allow for a c-compatible api
const std::set<int> *TaintEngine::getMemoryLabels(target_ulong addr) const {
    if (mem_.isTaintedAddress(addr)) {
        TaintLocation *loc = mem_.getTaintLocation(addr);
        return &loc->getLabels();
    }
    return nullptr;
}
