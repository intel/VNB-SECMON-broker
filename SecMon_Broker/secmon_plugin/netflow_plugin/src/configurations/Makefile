include ../../../../mk/platform.mk

INCLUDE = -I../../include -I../../../include

obj/%.o: %.c
	@echo -e '\t' CC $@
	@$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<

all:libconfigurations.a libserver.a

SOURCES := $(wildcard *.c)
CONFIGURATION_SOURCES := $(filter-out server.c, $(SOURCES))
CONFIGURATION_OBJS := $(patsubst %.c,obj/%.o,$(CONFIGURATION_SOURCES))

obj/server.o: server.c
	@echo -e '\t' CC $@
	@$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<

LIBS = -lpthread

create_dirs:
	@mkdir -p obj

libconfigurations.a:create_dirs $(CONFIGURATION_OBJS)
	@$(AR) -rcs ../../lib/$(LIB_PREFIX)configurations$(LIB_EXT) $(CONFIGURATION_OBJS)

libserver.a:obj/server.o
	@$(AR) -rcs ../../lib/$(LIB_PREFIX)server$(LIB_EXT) obj/server.o

.PHONY : clean
clean:
	@rm -rf obj/*.o
