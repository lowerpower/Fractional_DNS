SUBDIRS = src 

all:
	@$(MAKE) -C src -f makefile.linux

clean:
	@$(MAKE) -C src -f makefile.linux clean

#all: $(SUBDIRS)

#$(SUBDIRS):
#	$(MAKE) -C $@

#	.PHONY: $(SUBDIRS)


