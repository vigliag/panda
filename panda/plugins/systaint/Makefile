# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
CFLAGS+= -std=c++14 -g -fPIC -O1
LIBS+= -lprotobuf-c -lboost_regex

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o \
        $(PLUGIN_OBJ_DIR)/syscall_listener.o \
        $(PLUGIN_OBJ_DIR)/logging.o \
        $(PLUGIN_OBJ_DIR)/introspection.o
