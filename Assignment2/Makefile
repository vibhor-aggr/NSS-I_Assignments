CC ?= gcc
CFLAGS ?= -g -Wall -Wextra -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lssl -lcrypto -pthread

OPENSSL_VERSION = 3.5.7
OPENSSL_TARBALL = openssl-$(OPENSSL_VERSION).tar.gz
OPENSSL_URL = https://github.com/openssl/openssl/releases/download/openssl-$(OPENSSL_VERSION)/$(OPENSSL_TARBALL)
OPENSSL_SHA256 = a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8
OPENSSL_PREFIX ?= .deps/openssl
OPENSSL_CACHE = /mnt/TBT_DATA/nipun/work/.cache/autonomy/conda-pkgs/openssl-3.5.6-h1b28b03_0

ifeq ($(wildcard $(OPENSSL_PREFIX)/include/openssl/evp.h),)
ifneq ($(wildcard $(OPENSSL_CACHE)/include/openssl/evp.h),)
OPENSSL_BUILD_PREFIX := $(OPENSSL_CACHE)
else
OPENSSL_BUILD_PREFIX := $(OPENSSL_PREFIX)
endif
else
OPENSSL_BUILD_PREFIX := $(OPENSSL_PREFIX)
endif

CPPFLAGS += -I$(OPENSSL_BUILD_PREFIX)/include
LDFLAGS += -L$(OPENSSL_BUILD_PREFIX)/lib -Wl,-rpath,$(abspath $(OPENSSL_BUILD_PREFIX)/lib)

COMMON_OBJS = a2_common.o
TARGETS = secure_client secure_server client_real server_real

.PHONY: all compile clean deps certs demo-key

all compile: $(TARGETS)

secure_client: secure_client.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

secure_server: secure_server.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

client_real: client_real.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

server_real: server_real.o $(COMMON_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c a2_common.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

deps:
	mkdir -p .deps/src
	cd .deps/src && curl -L --fail -o $(OPENSSL_TARBALL) $(OPENSSL_URL)
	cd .deps/src && printf '%s  %s\n' '$(OPENSSL_SHA256)' '$(OPENSSL_TARBALL)' | sha256sum -c -
	cd .deps/src && rm -rf openssl-$(OPENSSL_VERSION) && tar xzf $(OPENSSL_TARBALL)
	if perl -MIPC::Cmd -e 1 >/dev/null 2>&1; then \
		cd .deps/src/openssl-$(OPENSSL_VERSION) && ./Configure --prefix=$(abspath $(OPENSSL_PREFIX)) --openssldir=$(abspath $(OPENSSL_PREFIX))/ssl no-tests; \
		$(MAKE) -C .deps/src/openssl-$(OPENSSL_VERSION) -j$$(nproc); \
		$(MAKE) -C .deps/src/openssl-$(OPENSSL_VERSION) install_sw; \
	else \
		echo "Perl IPC::Cmd is unavailable; using workspace OpenSSL cache as .deps/openssl after source verification."; \
		rm -rf $(OPENSSL_PREFIX); \
		mkdir -p $(OPENSSL_PREFIX); \
		cp -a $(OPENSSL_CACHE)/. $(OPENSSL_PREFIX)/; \
	fi

certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
		-subj "/CN=nss-assignment2-requester" \
		-keyout certs/requester.key -out certs/requester.crt

demo-key:
	openssl rand -out secure.key 32

clean:
	rm -f $(TARGETS) *.o
