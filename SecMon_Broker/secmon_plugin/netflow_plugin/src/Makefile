include ../../../mk/platform.mk

all:subdirs

SUBDIRS = filteragent configurations plugincore utils

.PHONY: subdirs $(SUBDIRS)

$(SUBDIRS):
	@$(MAKE) $(FLAGS) -C $@

subdirs:$(SUBDIRS)

.PHONY: clean

clean:
	@make clean -C filteragent
	@make clean -C configurations
	@make clean -C plugincore
	@make clean -C utils
	


