#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void tcgtaint_taint_register(bool istmp, unsigned char regno, int label);
void tcgtaint_taint_virtual_memory(target_ulong addr, unsigned int size, int label);
void tcgtaint_taint_physical_memory(hwaddr phyaddr, unsigned int size, int label);
void tcgtaint_clear_physical_memory(hwaddr phyaddr, unsigned int size);

void tcgtaint_physical_memory_labels_copy(target_ulong addr, uint32_t* out);

size_t tcgtaint_get_physical_memory_labels_count(target_ulong addr);
bool tcgtaint_is_virtual_memory_tainted(target_ulong addr);

void tcgtaint_set_taint_status(bool status);
bool tcgtaint_is_taint_instrumentation_on(void);
bool tcgtaint_is_taint_enabled(void);

#ifdef __cplusplus
};
#endif
