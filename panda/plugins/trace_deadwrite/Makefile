# Don't forget to add your plugin to config.panda!

# If you need custom CFLAGS or LIBS, set them up here
# -DUSE_STACK_HEURISTIC tries to detect thread switches by sudden
# jumps in the stack pointer
# LIBS+= 
LIBS+= -lcapstone

#CFLAGS += -c -Wno-deprecated -Wall -Werror -Wno-unknown-pragmas  -O3 -fomit-frame-pointer -fno-stack-protector -fno-strict-aliasing -DNDEBUG -DBIGARRAY_MULTIPLIER=2 -DUSING_XED -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX  

#CFLAGS += -c -Wno-deprecated -Wall -Wno-error -Wno-unknown-pragmas  -O3 -fomit-frame-pointer -fno-stack-protector -fno-strict-aliasing -DNDEBUG -DBIGARRAY_MULTIPLIER=2 -DUSING_XED -DTARGET_IA32E -DHOST_IA32E -fPIC -DTARGET_LINUX  
#-DIP_AND_CCT

MYINCLUDES = -isystem$(PLUGIN_SRC_DIR)/sparsehash-master/src
#INCLUDES = -I./sparsehash-master/src
CFLAGS += $(MYINCLUDES)

# from pri_simple
QEMU_CXXFLAGS:=$(filter-out -Wundef,$(QEMU_CXXFLAGS))

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o 
