# Don't forget to add your plugin to config.panda

# If you need custom CFLAGS or LIBS, set them up here
CFLAGS+= -I/usr/include/python3.6/
LIBS+= -rdynamic -lpython3.6m

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
        $(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o
