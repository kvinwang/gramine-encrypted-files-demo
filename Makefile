ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

APP_NAME = demo
SELF_EXE = target/release/$(APP_NAME)

.PHONY: all
all: $(SELF_EXE) $(APP_NAME).manifest
ifeq ($(SGX),1)
all: $(APP_NAME).manifest.sgx $(APP_NAME).sig
endif

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

# Note that we're compiling in release mode regardless of the DEBUG setting passed
# to Make, as compiling in debug mode results in an order of magnitude's difference in
# performance that makes testing by running a benchmark with ab painful. The primary goal
# of the DEBUG setting is to control Gramine's loglevel.
-include target/$(SELF_EXE).d # See also: .cargo/config.toml
$(SELF_EXE): Cargo.toml
	cargo build --release

$(APP_NAME).manifest: $(APP_NAME).manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		$< $@

# Make on Ubuntu <= 20.04 doesn't support "Rules with Grouped Targets" (`&:`),
# see the helloworld example for details on this workaround.
$(APP_NAME).manifest.sgx $(APP_NAME).sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: $(APP_NAME).manifest $(SELF_EXE)
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: start-gramine-server
run: all
	mkdir -p sealed
	$(GRAMINE) $(APP_NAME)

.PHONY: clean
clean:
	$(RM) -rf *.token *.sig *.manifest.sgx *.manifest result-* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock
