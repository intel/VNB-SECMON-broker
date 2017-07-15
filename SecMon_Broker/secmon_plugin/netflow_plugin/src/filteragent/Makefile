include ../../../../mk/platform.mk
DPDK_DIR = $(RTE_SDK)

INCLUDE = -I../../include -I. -I../../../include -I$(DPDK_DIR)/x86_64-native-linuxapp-gcc/include -include $(DPDK_DIR)/x86_64-native-linuxapp-gcc/include/rte_config.h

obj/%.o: %.c
	@echo -e '\t' CC $@
	@$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<

all:filter_agent.a

SOURCES := $(wildcard *.c)
OBJS := $(patsubst %.c,obj/%.o,$(SOURCES))
LIBS = -lpthread

create_directory:
	@mkdir -p obj

filter_agent.a:create_directory $(OBJS)
	@$(AR) -rcs  ../../lib/$(LIB_PREFIX)filter_agent$(LIB_EXT) $(OBJS)

.PHONY : clean
clean:
	@rm -rf obj/*.o
