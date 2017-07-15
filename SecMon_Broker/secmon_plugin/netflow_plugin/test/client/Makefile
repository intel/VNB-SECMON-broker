include ../../../mk/platform.mk

INCLUDE = -I../../include -I../../../include -I.

#executable with this name
TESTCLIENTEXE = test_client
CLIENTSTUB = stub_watch_handler

# linking flags here
LIBS = -lcurl -ljson 
SERVERLIB = ../../src/lib/libserver.a
CLIENT_CONFLIB = ../../src/lib/libconfigurations.a
CLIENT_UTILSLIB = ../../src/lib/libplugin_utils.a
PLUGIN_UTILS = ../../../utils/lib/libcommon_utils.a
CLIENTLIB = $(CLIENT_CONFLIB) $(CLIENT_UTILSLIB)
CLIENT_STUBSO = libclient_stub.so

BINDIR = bin
OBJDIR = obj
LIBDIR = lib
STUBDIR = ../../../stubs
RM = rm -rf

all:create_binary

create_dirs:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	@mkdir -p $(LIBDIR)
	@mkdir -p $(STUBDIR)/$(OBJDIR)

SOURCES := test_client.c
CLIENT_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SOURCES))

$(OBJDIR)/%.o: %.c
	@echo -e '\t' CC $@
	@$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<
	@$(MAKE) $(FLAGS) -C `pwd`/../../src/server
	@$(MAKE) $(FLAGS) -C `pwd`/../../src/client
	@$(MAKE) $(FLAGS) -C `pwd`/../../../utils

$(STUBDIR)/$(OBJDIR)/plugin_stub.o: $(STUBDIR)/plugin_stub.c
	@echo -e '\t' CC $@
	@$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<

$(BINDIR)/$(TESTCLIENTEXE): $(STUBDIR)/$(OBJDIR)/plugin_stub.o $(CLIENT_OBJS)
	@$(GCC) -shared -o $(CLIENT_STUBSO) -Wl,-whole-archive $(CLIENTLIB) $(SERVERLIB) $(PLUGIN_UTILS) -Wl,-no-whole-archive -lcurl -ljson
	@mv $(CLIENT_STUBSO) $(LIBDIR)/
	@$(GCC) -o $@ $(STUBDIR)/$(OBJDIR)/plugin_stub.o $(CLIENT_OBJS) $(LIBDIR)/$(CLIENT_STUBSO) $(LIBS)
	@echo "created binary for test_client successfully!"

$(BINDIR)/$(CLIENTSTUB): $(STUBDIR)/stub_handler.c
	@$(GCC) -o $@ $(CFLAGS) -DNETFLOW_PLUGIN `pwd`/$(STUBDIR)/stub_handler.c $(INCLUDE) $(LIBS)
	@echo "created binary for stub watch_handler successfully!"

create_binary: create_dirs $(BINDIR)/$(TESTCLIENTEXE) $(BINDIR)/$(CLIENTSTUB)
	@echo "stub created successfully for client"

.PHONY : clean
clean:
	@rm -rf $(OBJDIR)/*
	@rm -rf $(LIBDIR)/*
	@rm -rf $(BINDIR)/*
	@make clean -C ../../src
	@echo "clean successfully"

