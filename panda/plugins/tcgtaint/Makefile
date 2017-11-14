# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
CFLAGS+= -std=c++14 -fPIC -O2 -g
LIBS+=

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
        $(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
        $(PLUGIN_OBJ_DIR)/api.o \
        $(PLUGIN_OBJ_DIR)/logging.o \
        $(PLUGIN_OBJ_DIR)/notify_taint.o \
        $(PLUGIN_OBJ_DIR)/shadow.o \
        $(PLUGIN_OBJ_DIR)/taintengine.o
