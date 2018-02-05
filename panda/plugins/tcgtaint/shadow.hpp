//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TAINT_SHADOW_H_
#define SRC_QTRACE_TAINT_SHADOW_H_

#include "logging.hpp"
#include <algorithm>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <map>
#include "sparsepp/spp.h"

// TODO(vigliag) is it worth including panda/plugin.h 
// in here in order to get target_ulong?
#include "panda/plugin.h"

using Label = int;

//
// An instance of the TaintLocation class represents a tainted memory location
// or CPU register.
//
// Each instance of this class represents a single tainted byte. Tainted
// locations are characterized with one or more "taint labels", usually
// associated with specific input (or "source") bytes.
//
class TaintLocation {
  public:
    explicit TaintLocation() {}

    // Assign (move) two tainted locations
    void set(const TaintLocation &src) { labels_ = src.labels_; }

    // Combine two tainted locations
    void combine(const TaintLocation &src) {
        labels_.insert(src.labels_.begin(), src.labels_.end());
        if (labels_.size() > 100) {
            WARNING("More than 100 labels combined");
        }
    }

    // Copy taint labels to an output set
    void copy(std::set<int> &out) const {
        out.insert(labels_.begin(), labels_.end());
    }

    // Add a taint label to this tainted location
    inline void addLabel(int label) { labels_.insert(label); }

    // Check if this location has a specific taint label
    inline bool hasLabel(int label) const {
        return labels_.find(label) != labels_.end();
    }

    // Check if this location is tainted
    inline bool isTainted() const { return labels_.size() > 0; }

    // Remove all taint labels
    inline void clear() { labels_.clear(); }

    inline const std::set<int> &getLabels() { return labels_; }

    friend bool operator== (const TaintLocation &t1, const TaintLocation &t2){
        return t1.labels_ == t2.labels_;
    }
  private:
    std::set<Label> labels_;
};

using shadowmemory_t =
    spp::sparse_hash_map<target_ulong, std::shared_ptr<TaintLocation>>;

/**
 * @brief The ShadowMemory class is used to represent the taint status for the
 * emulated memory.
 * It uses a shadowmemory_t (map of taint locations) as underlying storage
 */
class ShadowMemory {
  public:
    explicit ShadowMemory() {}

    // Add a taint label to at the specified memory address
    void addLabel(target_ulong addr, int label) {
        if (mem_.find(addr) == mem_.end()) {
            mem_[addr] = std::shared_ptr<TaintLocation>(new TaintLocation);
        }

        mem_[addr]->addLabel(label);
    }

    // Taint propagation primitives
    void set(const TaintLocation *loc, target_ulong addr);
    void clear(target_ulong addr, unsigned int size = 1);

    // Check if a memory address is tainted
    inline bool isTaintedAddress(target_ulong addr) const {
        return mem_.find(addr) != mem_.end() && mem_.at(addr)->isTainted();
    }

    // Check if a memory address has a taint label
    inline bool hasLabel(target_ulong addr, int label) const {
        return mem_.find(addr) != mem_.end() && mem_.at(addr)->hasLabel(label);
    }

    void combine(const TaintLocation *loc, target_ulong addr);

    // Get the taint status of a (tainted) memory address
    inline TaintLocation *getTaintLocation(target_ulong addr) const {
        return mem_.at(addr).get();
    }

  private:
    shadowmemory_t mem_;
};


/**
 * @brief The ShadowMemory class is used to represent the taint status for the
 * emulated memory.
 * It uses a shadowmemory_t (map of taint locations) as underlying storage
 */
/*
class CondensedShadowMemory {
    struct RangeEntry {
        uint32_t addr;
        uint32_t length;
        TaintLocation tlocation;
    };

    void addToEntry(target_ulong addr, int label){
        auto &entry = mem_[addr];
        entry.length = 1;
        entry.addr = addr;
        entry.tlocation.addLabel(label);
    }

    void removeFromEntry(target_ulong addr, RangeEntry& existing){
        if (existing.addr == addr) {
            if(existing.length == 1){
                return; //it will simply be overwritten
            }
            //move one step forward
            existing.addr = addr + 1;
            mem_[addr + 1] = existing;
            return;
        }

        if(existing.addr + existing.length == addr){
            //make shorter by one
            existing.length -= 1;
            return;
        }

        //it is in the middle
        auto oldlen = existing.length;
        existing.length = addr - existing.addr; //resize first part

        //copy first part to second part
        auto& secondpart = mem_[addr + 1];
        secondpart.addr = addr + 1;
        secondpart.length = (existing.addr + oldlen) - (addr+ 1);
    }

  public:
    explicit CondensedShadowMemory() {}




    // Add a taint label to at the specified memory address
    void addLabel(target_ulong addr, int label) {

        auto it_after = mem_.upper_bound(addr);
        if(it_after == mem_.begin()){
            //can happen if .begin() == .end(), or if there's no smaller pointer
            addToEntry(addr, label);
        }

        it_after--;
        auto &firstLower_tuple = *it_after;
        auto &firstLower_addr = firstLower_tuple.first;
        auto &firstLower_entry = firstLower_tuple.second;

        assert(firstLower_addr == firstLower_entry.addr);

        if(firstLower_addr <= addr && addr < (firstLower_addr + firstLower_entry.length) ){
            if (firstLower_entry.tlocation.hasLabel(label)){
                return;
            } else {
                removeFromEntry(addr, firstLower_entry);
                addToEntry(addr, label);
                return;
            }
        }

        if (mem_.find(addr) == mem_.end()) {
            mem_[addr] = std::shared_ptr<TaintLocation>(new TaintLocation);
        }
        mem_[addr]->addLabel(label);
    }

    // Taint propagation primitives
    void set(const TaintLocation *loc, target_ulong addr){

    };

    void clear(target_ulong addr, unsigned int size = 1);

    // Check if a memory address is tainted
    inline bool isTaintedAddress(target_ulong addr) const {
        return mem_.find(addr) != mem_.end() && mem_.at(addr)->isTainted();
    }

    // Check if a memory address has a taint label
    inline bool hasLabel(target_ulong addr, int label) const {
        return mem_.find(addr) != mem_.end() && mem_.at(addr)->hasLabel(label);
    }

    void combine(const TaintLocation *loc, target_ulong addr);

    // Get the taint status of a (tainted) memory address
    inline TaintLocation *getTaintLocation(target_ulong addr) const {
        return mem_.at(addr).get();
    }

  private:
    std::map<target_ulong, RangeEntry> mem_;
};
*/
/**
 * @brief The ShadowRegister class represents the tainted status of a CPU
 *  register. It is implemented as an array of TaintLocation.
 */
class ShadowRegister {
  public:
    // Initialize a tainted register, given its size (in bytes)
    // CHECK(vigliag) it was previously initialized to target_ulong,
    // but the tcg target architecture (and tcg temp registers) are 64bit
    // (tcg_target_ulong?)
    explicit ShadowRegister(unsigned int size = sizeof(uint64_t))
        : size_(size) {
        reg_ = new TaintLocation[size];
    }

    ~ShadowRegister() { delete[] reg_; }

    // Assign a shadow register, copying the taint information from the source
    // to the destination (this) operand
    void set(const ShadowRegister &other);
    void set(const TaintLocation *loc, int offset);

    // Add a taint label
    inline void set(unsigned int label, unsigned int start = 0, int size = -1) {
        if (size == -1) {
            size = size_;
        }

        for (unsigned int i = start; i < (start + size); i++) {
            reg_[i].addLabel(label);
        }
    }

    // Copy taint information
    inline void set(const TaintLocation *loc, unsigned int offset = 0) {
        reg_[offset].set(*loc);
    }

    // Clear taint information
    void clear(unsigned int offset = 0, int size = -1) {
        if (size == -1) {
            size = size_ - offset;
        }

        for (unsigned int i = offset; i < (offset + size); i++) {
            reg_[i].clear();
        }
    }

    void getAllLabels(std::set<Label>* out) const {
        if(ignored){
            return;
        }
        for (int i = 0; i < size_; i++) {
            for (const Label l : reg_[i].getLabels()) {
                out->insert(l);
            }
        }
    }

    // Combine taint information from the source and the destination (this)
    // operand
    void combine(const ShadowRegister &other);
    void combine(const TaintLocation *loc, int offset);

    // Get the size of this register
    inline unsigned getSize() const { return (unsigned)size_; }

    // Check if this register is tainted
    bool isTainted() const;
    bool isTaintedByte(unsigned int offset) const;

    // Get the taint status of a (tainted) CPU register
    inline TaintLocation *getTaintLocation(unsigned int offset) const {
        return &reg_[offset];
    }

    // Check if this shadow register has the specified taint label
    bool hasLabel(int label) const;

    // Set register name
    void setName(const std::string newname) { name_ = newname; }

    // Get register name
    const std::string getName() const { return name_; }

    // Get register name (c version)
    const char * getCName() const { return name_.empty() ? NULL : name_.c_str(); }

    // Gets the first label at the first byte (useful for debugging purposes)
    int firstLabel() const{
        if(!reg_[0].isTainted())
            return 0;
        else{
            return *reg_[0].getLabels().begin();
        }
    }

    void ignore(){
        ignored = true;
    }

    bool isIgnored() const{
        return ignored;
    }

  private:
    int size_;
    bool ignored = false; //an ignored register is always untainted
    TaintLocation *reg_;
    std::string name_;
};

#endif // SRC_QTRACE_TAINT_SHADOW_H_
