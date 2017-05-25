# Include files and lib from LLVM
QEMU_CXXFLAGS+= $(LLVM_CXXFLAGS) -Wno-type-limits -Wno-cast-qual

# plugin source file depends on shadow memory stuff in panda directory
#$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME).o: \
#    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME).cpp \
#    $(wildcard $(SRC_PATH)/panda/*.[ch]) $(wildcard $(SRC_PATH)/panda/*.cpp)

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
        $(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o\
        $(PLUGIN_OBJ_DIR)/panda_memlog.o\
        $(PLUGIN_OBJ_DIR)/panda_dynval_inst.o\
        $(PLUGIN_OBJ_DIR)/guestarch.o\
        $(PLUGIN_OBJ_DIR)/tubtf.o

# Testing tool for LLVM traces
#$(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_test: \
#    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME)_test.h \
#    $(PLUGIN_SRC_ROOT)/$(PLUGIN_NAME)/$(PLUGIN_NAME)_test.cpp
#
#	$(call quiet-command,$(CXX) $(QEMU_INCLUDES) $(CXXFLAGS) \
#            -o $@ $^ $(LIBS),"  PLUGIN_TEST  $@")

#ifdef CONFIG_LLVM
#all: $(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so \
#    $(PLUGIN_TARGET_DIR)/$(PLUGIN_NAME)_test
#endif

