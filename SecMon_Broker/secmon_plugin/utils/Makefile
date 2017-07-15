include ../../mk/platform.mk
DPDK_DIR = $(RTE_SDK)

INCLUDE = -I../include -I$(DPDK_DIR)/x86_64-native-linuxapp-gcc/include -include $(DPDK_DIR)/x86_64-native-linuxapp-gcc/include/rte_config.h

obj/%.o: %.c
	@echo -e '\t' CC $@
	$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<

all:common_utils.a

SOURCES := $(wildcard *.c)
OBJS := $(patsubst %.c,obj/%.o,$(SOURCES))
LIBS = -lpthread

create_directory:
	@mkdir -p obj
	@mkdir -p lib

common_utils.a:create_directory $(OBJS)
	$(AR) -rcs lib/$(LIB_PREFIX)common_utils$(LIB_EXT) $(OBJS)

.PHONY : clean
clean:
	rm -rf obj/*.o
	rm -rf lib/*
