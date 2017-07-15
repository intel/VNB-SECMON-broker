include ../../../../mk/platform.mk

INCLUDE = -I../../include -I../../../include

obj/%.o: %.c
	@echo -e '\t' CC $@
	$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<

all:plugin_utils.a

SOURCES := $(wildcard *.c)
OBJS := $(patsubst %.c,obj/%.o,$(SOURCES))
LIBS = -lpthread

create_directory:
	@mkdir -p obj

plugin_utils.a:create_directory $(OBJS)
	$(AR) -rcs ../../lib/$(LIB_PREFIX)plugin_utils$(LIB_EXT) $(OBJS)

.PHONY : clean
clean:
	rm -rf obj/*.o
