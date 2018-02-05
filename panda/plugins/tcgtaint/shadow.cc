//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "shadow.hpp"

#include <algorithm>
#include <assert.h>

void ShadowRegister::set(const ShadowRegister &other) {
    if(other.ignored) return;
    for (int i = 0; i < std::min(size_, other.size_); i++) {
        reg_[i].set(other.reg_[i]);
    }
}

void ShadowRegister::combine(const ShadowRegister &other) {
    //TODO combine is implemented wrong, it shouldn't work byte-per-byte at all
    if(other.ignored) return;
    for (int i = 0; i < std::min(size_, other.size_); i++) {
        reg_[i].combine(other.reg_[i]);
    }
}

void ShadowRegister::combine(const TaintLocation *loc, int offset) {
    assert(offset < size_);
    reg_[offset].combine(*loc);
}

void ShadowRegister::set(const TaintLocation *loc, int offset) {
    assert(offset < size_);
    reg_[offset].set(*loc);
}

bool ShadowRegister::isTainted() const {
    if(ignored){
        return false;
    }
    for (int i = 0; i < size_; i++) {
        if (reg_[i].isTainted()) {
            return true;
        }
    }

    return false;
}

bool ShadowRegister::isTaintedByte(unsigned int offset) const {
    if(ignored){
        return false;
    }
    assert(offset < size_);
    return reg_[offset].isTainted();
}

bool ShadowRegister::hasLabel(int label) const {
    if(ignored){
        return false;
    }
    for (int i = 0; i < size_; i++) {
        if (reg_[i].hasLabel(label)) {
            return true;
        }
    }
    return false;
}

void ShadowMemory::set(const TaintLocation *loc, target_ulong addr) {
    if (mem_.find(addr) == mem_.end()) {
        mem_[addr] = std::make_shared<TaintLocation>();
    }

    mem_[addr]->set(*loc);
    if (mem_.size() % 10000 == 0) {
        INFO("STATS %d memory locations tainted", mem_.size());
    }
}

void ShadowMemory::clear(target_ulong addr, unsigned int size) {
    for (unsigned int i = 0; i < size; i++) {
        if (mem_.find(addr + i) != mem_.end()) {
            mem_.erase(addr + i);
        }
    }
}

void ShadowMemory::combine(const TaintLocation *loc, target_ulong addr) {
    if (mem_.find(addr) == mem_.end()) {
        mem_[addr] = std::shared_ptr<TaintLocation>(new TaintLocation);
    }

    mem_[addr]->combine(*loc);
}
