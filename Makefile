# Builds all three reflectors: make, make clean, make install
# or just one: make YSFReflector

REFLECTORS = YSFReflector NXDNReflector P25Reflector

all:		$(REFLECTORS)

$(REFLECTORS):
		$(MAKE) -C $@

install:	all
		for d in $(REFLECTORS); do $(MAKE) -C $$d install || exit 1; done

clean:
		for d in $(REFLECTORS); do $(MAKE) -C $$d clean || exit 1; done

.PHONY:		all install clean $(REFLECTORS)
