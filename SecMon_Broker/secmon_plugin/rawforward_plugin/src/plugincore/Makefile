include ../../../../mk/platform.mk
DPDK_DIR = $(RTE_SDK)

INCLUDE = -I../../include -I../../../include -I$(DPDK_DIR)/x86_64-native-linuxapp-gcc/include -include $(DPDK_DIR)/x86_64-native-linuxapp-gcc/include/rte_config.h

obj/%.o: %.c
	@echo -e '\t' CC $@
	@$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<

all:plugin_core.a

SOURCES := $(wildcard *.c)
OBJS := $(patsubst %.c,obj/%.o,$(SOURCES))
LIBS = -lpthread

create_directories:
	@mkdir -p obj

plugin_core.a:create_directories $(OBJS)
	@$(AR) -rcs ../../lib/$(LIB_PREFIX)plugin_core$(LIB_EXT) $(OBJS)

.PHONY: clean
clean:
	@rm -rf obj/*.o

