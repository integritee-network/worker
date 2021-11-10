# Copyright 2021 Integritee AG and Supercomputing Systems AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

######## Update SGX SDK ########
include UpdateRustSGXSDK.mk

######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 0
SGX_PRODUCTION ?= 0

SKIP_WASM_BUILD = 1
# include the build settings from rust-sgx-sdk
include rust-sgx-sdk/buildenv.mk
# use this manually to update sdk
#include UpdateRustSGXSDK.mk

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
ifeq ($(SGX_PRODUCTION), 1)
$(error Cannot set SGX_DEBUG and SGX_PRODUCTION at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
	# we build with cargo --release, even in SGX DEBUG mode
	SGX_COMMON_CFLAGS += -O0 -g -ggdb
	# cargo sets this automatically, cannot use 'debug'
	OUTPUT_PATH := release
	CARGO_TARGET := --release
else
	SGX_COMMON_CFLAGS += -O2
	OUTPUT_PATH := release
	CARGO_TARGET := --release
endif

SGX_COMMON_CFLAGS += -fstack-protector

ifeq ($(SGX_PRODUCTION), 1)
	SGX_ENCLAVE_MODE = "Production Mode"
	SGX_ENCLAVE_CONFIG = "enclave-runtime/Enclave.config.production.xml"
	SGX_SIGN_KEY = $(SGX_COMMERCIAL_KEY)
	WORKER_FEATURES = --features=production
else
	SGX_ENCLAVE_MODE = "Development Mode"
	SGX_ENCLAVE_CONFIG = "enclave-runtime/Enclave.config.xml"
	SGX_SIGN_KEY = "enclave-runtime/Enclave_private.pem"
	WORKER_FEATURES = --features=default
endif

# check if running on Jenkins
ifdef BUILD_ID
	CARGO_TARGET += --verbose
endif

######## CUSTOM settings ########
CUSTOM_LIBRARY_PATH := ./lib
CUSTOM_BIN_PATH := ./bin
CUSTOM_EDL_PATH := ./rust-sgx-sdk/edl
CUSTOM_COMMON_PATH := ./rust-sgx-sdk/common

######## EDL settings ########
Enclave_EDL_Files := enclave-runtime/Enclave_t.c enclave-runtime/Enclave_t.h service/Enclave_u.c service/Enclave_u.h

######## Integritee-service settings ########
Worker_Rust_Flags := $(CARGO_TARGET) $(WORKER_FEATURES)
Worker_SRC_Files := $(shell find service/ -type f -name '*.rs') $(shell find service/ -type f -name 'Cargo.toml')
Worker_Include_Paths := -I ./service -I./include -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
Worker_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Worker_Include_Paths)

Worker_Rust_Path := target/$(OUTPUT_PATH)
Worker_Enclave_u_Object :=service/libEnclave_u.a
Worker_Name := bin/app

######## Integritee-cli settings ########
Client_SRC_Path := cli
STF_SRC_Path := app-libs/stf
Client_Rust_Flags := $(CARGO_TARGET)
Client_SRC_Files := $(shell find $(Client_SRC_Path)/ -type f -name '*.rs') $(shell find $(STF_SRC_Path)/ -type f -name '*.rs') $(shell find $(Client_SRC_Path)/ -type f -name 'Cargo.toml')
Client_Include_Paths := -I ./$(Client_SRC_Path) -I./include -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
Client_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Client_Include_Paths)

Client_Rust_Path := target/$(OUTPUT_PATH)
Client_Path := bin
Client_Binary := integritee-cli
Client_Name := $(Client_Path)/$(Client_Binary)

######## Enclave settings ########
ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto
KeyExchange_Library_Name := sgx_tkey_exchange
ProtectedFs_Library_Name := sgx_tprotected_fs

RustEnclave_C_Files := $(wildcard ./enclave-runtime/*.c)
RustEnclave_C_Objects := $(RustEnclave_C_Files:.c=.o)
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ./enclave-runtime -I./include

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) $(ENCLAVE_CFLAGS) $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -l$(ProtectedFs_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,--version-script=enclave-runtime/Enclave.lds \
	$(ENCLAVE_LDFLAGS)

RustEnclave_Name := enclave-runtime/enclave.so
Signed_RustEnclave_Name := bin/enclave.signed.so

######## Targets ########
.PHONY: all
all: $(Client_Name) $(Worker_Name) $(Signed_RustEnclave_Name)
service: $(Worker_Name)
client: $(Client_Name)
githooks: .git/hooks/pre-commit

######## EDL objects ########
$(Enclave_EDL_Files): $(SGX_EDGER8R) enclave-runtime/Enclave.edl
	$(SGX_EDGER8R) --trusted enclave-runtime/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --trusted-dir enclave-runtime
	$(SGX_EDGER8R) --untrusted enclave-runtime/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --untrusted-dir service
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## Integritee-service objects ########
service/Enclave_u.o: $(Enclave_EDL_Files)
	@$(CC) $(Worker_C_Flags) -c service/Enclave_u.c -o $@
	@echo "CC   <=  $<"

$(Worker_Enclave_u_Object): service/Enclave_u.o
	$(AR) rcsD $@ $^
	cp $(Worker_Enclave_u_Object) ./lib

$(Worker_Name): $(Worker_Enclave_u_Object) $(Worker_SRC_Files)
	@echo
	@echo "Building the integritee-service"
	@cd service && SGX_SDK=$(SGX_SDK) SGX_MODE=$(SGX_MODE) cargo build $(Worker_Rust_Flags)
	@echo "Cargo  =>  $@"
	cp $(Worker_Rust_Path)/integritee-service ./bin

######## Integritee-client objects ########
$(Client_Name): $(Client_SRC_Files)
	@echo
	@echo "Building the integritee-cli"
	@cd $(Client_SRC_Path) && cargo build $(Client_Rust_Flags)
	@echo "Cargo  =>  $@"
	cp $(Client_Rust_Path)/$(Client_Binary) ./bin

######## Enclave objects ########
enclave-runtime/Enclave_t.o: $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c enclave-runtime/Enclave_t.c -o $@
	@echo "CC   <=  $<"

$(RustEnclave_Name): enclave enclave-runtime/Enclave_t.o
	@echo Compiling $(RustEnclave_Name)
	@$(CXX) enclave-runtime/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name)
	@echo
	@echo "Signing the enclave: $(SGX_ENCLAVE_MODE)"
	$(SGX_ENCLAVE_SIGNER) sign -key $(SGX_SIGN_KEY) -enclave $(RustEnclave_Name) -out $@ -config $(SGX_ENCLAVE_CONFIG)
	@echo "SIGN =>  $@"
	@echo
	@echo "Enclave is in $(SGX_ENCLAVE_MODE)"

.PHONY: enclave
enclave:
	@echo
	@echo "Building the enclave"
	$(MAKE) -C ./enclave-runtime/

.git/hooks/pre-commit: .githooks/pre-commit
	@echo "Installing git hooks"
	cp .githooks/pre-commit .git/hooks

.PHONY: clean
clean:
	@echo "Removing the compiled files"
	@rm -f $(Client_Name) $(Worker_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) \
 			enclave-runtime/*_t.* \
 			service/*_u.* \
 			lib/*.a \
 			bin/*.bin
	@echo "cargo clean in enclave directory"
	@cd enclave-runtime && cargo clean
	@echo "cargo clean in root directory"
	@cargo clean

.PHONY: pin-sgx
pin-sgx:
	@echo "Pin sgx dependencies to 6cf73140d5e9b05366a2ae4f8fe8141449e7204f"
	@cd enclave-runtime && cargo update -p sgx_tstd --precise 6cf73140d5e9b05366a2ae4f8fe8141449e7204f
	@cargo update -p sgx_tstd --precise 6cf73140d5e9b05366a2ae4f8fe8141449e7204f

mrenclave:
	@$(SGX_ENCLAVE_SIGNER) dump -enclave ./bin/enclave.signed.so -dumpfile df.out && ./extract_identity < df.out && rm df.out

mrsigner:
	@$(SGX_ENCLAVE_SIGNER) dump -enclave ./bin/enclave.signed.so -dumpfile df.out && ./extract_identity --mrsigner < df.out && rm df.out

.PHONY: identity
identity: mrenclave mrsigner

.PHONY: help
help:
	@echo "Available targets"
	@echo "  all      - builds all targets (default)"
	@echo "  service   - builds the integritee-service"
	@echo "  client   - builds the integritee-cli"
	@echo "  githooks - installs the git hooks (copy .githooks/pre-commit to .git/hooks)"
	@echo ""
	@echo "  clean   - cleanup"
	@echo ""
	@echo "Compilation options. Prepend them to the make command. Example: 'SGX_MODE=SW make'"
	@echo "  SGX_MODE"
	@echo "    HW (default): Use SGX hardware"
	@echo "    SW: Simulation mode"
	@echo "  SGX_DEBUG"
	@echo "    0 (default): No debug information, optimization level 2, cargo release build"
	@echo "    1: Debug information, optimization level 0, cargo debug build"
	@echo "  SGX_PRODUCTION"
	@echo "    0 (default): Using SGX development environment"
	@echo "    1: Using SGX production environment"
