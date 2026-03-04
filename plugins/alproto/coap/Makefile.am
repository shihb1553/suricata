if !DEBUG
RELEASE = --release
endif

if RUST_BUILD_STD
NIGHTLY_ARGS = -Z build-std
endif

if DEBUG
RUST_FEATURES +=	debug
TARGET_PATH = debug
else
TARGET_PATH = release
endif

if DEBUG_VALIDATION
RUST_FEATURES +=	debug-validate
endif

if RUST_CROSS_COMPILE
RUST_TARGET = --target $(host_triplet)
endif

CARGO_ENV =	@rustup_home@ \
		CARGO_HOME="$(CARGO_HOME)" \
		CARGO_TARGET_DIR="$(abs_top_builddir)/rust/target"

CARGO_ENV +=	LOCALSTATEDIR=$(e_localstatedir)

install:
	$(MKDIR_P) "$(DESTDIR)$(libdir)/suricata"
	$(INSTALL_DATA) $(abs_top_builddir)/rust/target/$(TARGET_PATH)/libalproto_coap.so "$(DESTDIR)$(libdir)/suricata/alproto_coap.so"

all-local:
	CC="$(CC)" AR="$(AR)" RANLIB="$(RANLIB)"\
		$(CARGO_ENV) \
		$(CARGO) build $(RELEASE) $(NIGHTLY_ARGS) \
			--features "$(RUST_FEATURES)" $(RUST_TARGET)
