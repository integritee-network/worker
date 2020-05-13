# Copyright 2020 Supercomputing Systems AG
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
# include UpdateRustSGXSDK.mk

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
	SGX_COMMON_CFLAGS += -O0 -g -ggdb
	OUTPUT_PATH := debug
	CARGO_TARGET :=
else
	SGX_COMMON_CFLAGS += -O2
	OUTPUT_PATH := release
	CARGO_TARGET := --release
endif

ifeq ($(SGX_PRODUCTION), 1)
	SGX_ENCLAVE_MODE = "Production Mode"
	SGX_ENCLAVE_CONFIG = "enclave/Enclave.config.production.xml"
	SGX_SIGN_KEY = $(SGX_COMMERCIAL_KEY)
	WORKER_FEATURES = --features=production
else
	SGX_ENCLAVE_MODE = "Development Mode"
	SGX_ENCLAVE_CONFIG = "enclave/Enclave.config.xml"
	SGX_SIGN_KEY = "enclave/Enclave_private.pem"
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
Enclave_EDL_Files := enclave/Enclave_t.c enclave/Enclave_t.h worker/Enclave_u.c worker/Enclave_u.h

######## SubstraTEE-worker settings ########
Worker_Rust_Flags := $(CARGO_TARGET) $(WORKER_FEATURES)
Worker_SRC_Files := $(shell find worker/ -type f -name '*.rs') $(shell find worker/ -type f -name 'Cargo.toml')
Worker_Include_Paths := -I ./worker -I./include -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
Worker_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Worker_Include_Paths)

Worker_Rust_Path := target/$(OUTPUT_PATH)
Worker_Enclave_u_Object :=worker/libEnclave_u.a
Worker_Name := bin/app

######## SubstraTEE-client settings ########
Client_SRC_Path := client
Client_Rust_Flags := $(CARGO_TARGET)
Client_SRC_Files := $(shell find $(Client_SRC_Path)/ -type f -name '*.rs') $(shell find $(Client_SRC_Path)/ -type f -name 'Cargo.toml')
Client_Include_Paths := -I ./$(Client_SRC_Path) -I./include -I$(SGX_SDK)/include -I$(CUSTOM_EDL_PATH)
Client_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Worker_Include_Paths)

Client_Rust_Path := target/$(OUTPUT_PATH)
Client_Path := bin
Client_Binary := substratee-client
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

RustEnclave_C_Files := $(wildcard ./enclave/*.c)
RustEnclave_C_Objects := $(RustEnclave_C_Files:.c=.o)
RustEnclave_Include_Paths := -I$(CUSTOM_COMMON_PATH)/inc -I$(CUSTOM_EDL_PATH) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/stlport -I$(SGX_SDK)/include/epid -I ./enclave -I./include

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -l$(ProtectedFs_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,--version-script=enclave/Enclave.lds \
	$(ENCLAVE_LDFLAGS)

RustEnclave_Name := enclave/enclave.so
Signed_RustEnclave_Name := bin/enclave.signed.so

######## Targets ########
.PHONY: all
all: $(Client_Name) $(Worker_Name) $(Signed_RustEnclave_Name)
worker: $(Worker_Name)
client: $(Client_Name)
githooks: .git/hooks/pre-commit

######## EDL objects ########
$(Enclave_EDL_Files): $(SGX_EDGER8R) enclave/Enclave.edl
	$(SGX_EDGER8R) --trusted enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --trusted-dir enclave
	$(SGX_EDGER8R) --untrusted enclave/Enclave.edl --search-path $(SGX_SDK)/include --search-path $(CUSTOM_EDL_PATH) --untrusted-dir worker
	@echo "GEN  =>  $(Enclave_EDL_Files)"

######## SubstraTEE-worker objects ########
worker/Enclave_u.o: $(Enclave_EDL_Files)
	@$(CC) $(Worker_C_Flags) -c worker/Enclave_u.c -o $@
	@echo "CC   <=  $<"

$(Worker_Enclave_u_Object): worker/Enclave_u.o
	$(AR) rcsD $@ $^
	cp $(Worker_Enclave_u_Object) ./lib

$(Worker_Name): $(Worker_Enclave_u_Object) $(Worker_SRC_Files)
	@echo
	@echo "Building the substraTEE-worker"
	@cd worker && SGX_SDK=$(SGX_SDK) cargo build $(Worker_Rust_Flags)
	@echo "Cargo  =>  $@"
	cp $(Worker_Rust_Path)/substratee-worker ./bin
	cp $(Worker_Rust_Path)/substratee-worker ./bin2

######## SubstraTEE-client objects ########
$(Client_Name): $(Client_SRC_Files)
	@echo
	@echo "Building the substraTEE-client"
	@cd $(Client_SRC_Path) && cargo build $(Client_Rust_Flags)
	@echo "Cargo  =>  $@"
	cp $(Client_Rust_Path)/$(Client_Binary) ./bin

######## Enclave objects ########
enclave/Enclave_t.o: $(Enclave_EDL_Files)
	@$(CC) $(RustEnclave_Compile_Flags) -c enclave/Enclave_t.c -o $@
	@echo "CC   <=  $<"

$(RustEnclave_Name): enclave enclave/Enclave_t.o
	@echo Compiling $(RustEnclave_Name)
	@$(CXX) enclave/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
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
	$(MAKE) -C ./enclave/

.git/hooks/pre-commit: .githooks/pre-commit
	@echo "Installing git hooks"
	cp .githooks/pre-commit .git/hooks

.PHONY: clean
clean:
	@echo "Removing the compiled files"
	@rm -f $(Client_Name) $(Worker_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) enclave/*_t.* worker/*_u.* lib/*.a bin/*.bin
	@echo "cargo clean and remove Cargo.lock in enclave directory"
	@cd enclave && cargo clean && rm -f Cargo.lock
	@echo "cargo clean and remove Cargo.lock in root directory"
	@cargo clean && rm -f Cargo.lock

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
	@echo "  worker   - builds the substraTEE-worker"
	@echo "  client   - builds the substraTEE-client"
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
