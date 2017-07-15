include ../../../../mk/platform.mk

INCLUDE = -I../../include -I../../../include -I.

#executable with this name
TESTSERVEREXE = test_server
SERVERSTUB = stub_watch_handler

# linking flags here
LIBS = -lcurl -ljson 
SERVERLIB = ../../lib/libserver.a

BINDIR = bin
OBJDIR = obj
STUBDIR = ../../../stubs
RM = rm -rf

all:create_binary

create_dirs:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(BINDIR)
	@mkdir -p $(STUBDIR)/$(OBJDIR)

SOURCES := test_server.c stub_json_pasrer.c
SERVER_OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SOURCES))

$(OBJDIR)/%.o: %.c
	@echo -e '\t' CC $@
	@$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<
	@$(MAKE) $(FLAGS) -C `pwd`/../../src/configurations

$(STUBDIR)/$(OBJDIR)/client_stub.o: $(STUBDIR)/client_stub.c
	@echo -e '\t' CC $@
	@$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<

$(STUBDIR)/$(OBJDIR)/plugin_stub.o: $(STUBDIR)/plugin_stub.c
	@echo -e '\t' CC $@
	@$(GCC) $(CFLAGS) $(INCLUDE) -fPIC -c -o $@ $<

$(BINDIR)/$(TESTSERVEREXE): $(STUBDIR)/$(OBJDIR)/client_stub.o $(STUBDIR)/$(OBJDIR)/plugin_stub.o $(SERVER_OBJS)
	@$(GCC) -o $@ $(STUBDIR)/$(OBJDIR)/client_stub.o $(STUBDIR)/$(OBJDIR)/plugin_stub.o $(SERVER_OBJS) $(LIBS) $(SERVERLIB)
	@echo "created binary for test_server successfully!"

$(BINDIR)/$(SERVERSTUB): $(STUBDIR)/stub_handler.c
	@$(GCC) -o $@ $(CFLAGS) -DNETFLOW_PLUGIN `pwd`/$(STUBDIR)/stub_handler.c $(INCLUDE) $(LIBS)
	@echo "created binary for stub watch_handler successfully!"

create_binary: create_dirs $(BINDIR)/$(TESTSERVEREXE) $(BINDIR)/$(SERVERSTUB)
	@echo "stub created successfully for server"

.PHONY : clean
clean:
	@$(RM) $(OBJDIR)/*.o
	@$(RM) $(BINDIR)/*
	@make clean -C ../../src/configurations
	@echo "clean successfully"


