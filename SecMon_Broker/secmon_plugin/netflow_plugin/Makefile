ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable to dpdk root folder")
endif

include ../../mk/platform.mk

all:libnetflow.so

SUBDIRS = src `pwd`/../utils
.PHONY: subdirs $(SUBDIRS)

$(SUBDIRS):
	@$(MAKE) $(FLAGS) -C $@

subdirs:$(SUBDIRS)

create_directories:
	@mkdir -p lib
	@mkdir -p build

libnetflow.so:create_directories subdirs
	@cp ../utils/lib/* lib/
	@$(GCC) -shared -o libnetflow.so -Wl,-whole-archive lib/libconfigurations.a lib/libplugin_utils.a lib/libplugin_core.a lib/libfilter_agent.a  lib/libserver.a lib/libcommon_utils.a -Wl,-no-whole-archive -lcurl -ljson
	@mv libnetflow.so build/

.PHONY: clean

clean:
	@rm -rf lib/*
	@rm -rf build/*
	@make clean -C src

