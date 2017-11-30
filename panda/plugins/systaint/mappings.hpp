#include <map>
#include <boost/icl/
using Address = uint32_t;

/* Stacks from

'_KPROCESS' : [ 0x160, {
'ThreadListHead' : [ 0x30, ['_LIST_ENTRY']],
LIST ENTRY is this thing:

typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY  *Flink;
  struct _LIST_ENTRY  *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

*/

void getStacks(CPUState* cpu, std::map<Address, std::string>& address_map){

}

/* Heaps from PEB

'NumberOfHeaps' : [ 0xe8, ['unsigned long']],
'ProcessHeaps' : [ 0xf0, ['pointer64', ['pointer64', ['void']]]],

*/

/** Updates the current memory map, returns true if the memory map has changed*/
bool updateMemoryMap(CPUState* cpu, std::map<Address, std::string>& address_map){

}

struct SectionInfo {
    std::string sectionName;
    int offset;
};

class AddressMapper{
public:
    const std::string& resolveAddress()
};
