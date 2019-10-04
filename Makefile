# Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of Baidu, Inc., nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

# +----------------------------------------------------------------------------+
# |                                                                            |
# |                 THIS FILE CONTAINS MODIFICATIONS                           |
# |                DON'T OVERWRITE THE CONTENT BLINDLY                         |
# |                                                                            |
# +----------------------------------------------------------------------------+

######## Update SGX SDK ########
include UpdateRustSGXSDK.mk

######## SGX SDK Settings ########
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0

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

######## CUSTOM settings ########
CUSTOM_LIBRARY_PATH := ./lib
CUSTOM_BIN_PATH := ./bin
CUSTOM_EDL_PATH := ./rust-sgx-sdk/edl
CUSTOM_COMMON_PATH := ./rust-sgx-sdk/common

######## EDL settings ########
Enclave_EDL_Files := enclave/Enclave_t.c enclave/Enclave_t.h worker/Enclave_u.c worker/Enclave_u.h

######## SubstraTEE-worker settings ########
Worker_Rust_Flags := $(CARGO_TARGET)
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
Client_Binary := substratee_client
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

RustEnclave_Link_Libs := -L$(CUSTOM_LIBRARY_PATH) -lcompiler-rt-patch -lenclave
RustEnclave_Compile_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(RustEnclave_Include_Paths)
RustEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -l$(Service_Library_Name) -l${ProtectedFs_Library_Name} -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) $(RustEnclave_Link_Libs) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--gc-sections \
	-Wl,--version-script=enclave/Enclave.lds

RustEnclave_Name := enclave/enclave.so
Signed_RustEnclave_Name := bin/enclave.signed.so

######## Targets ########
.PHONY: all
all: $(Client_Name) $(Worker_Name) $(Signed_RustEnclave_Name)
worker: $(Worker_Name)
client: $(Client_Name)

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
	cp $(Worker_Rust_Path)/substratee_worker ./bin
	cp $(Worker_Rust_Path)/substratee_worker ./bin2

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

$(RustEnclave_Name): enclave compiler-rt enclave/Enclave_t.o
	cp ./rust-sgx-sdk/compiler-rt/libcompiler-rt-patch.a ./lib
	@$(CXX) enclave/Enclave_t.o -o $@ $(RustEnclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_RustEnclave_Name): $(RustEnclave_Name)
	@echo
	@echo "Signing the enclave"
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/Enclave_private.pem -enclave $(RustEnclave_Name) -out $@ -config enclave/Enclave.config.xml
	@echo "SIGN =>  $@"


.PHONY: enclave
enclave:
	@echo
	@echo "Building the enclave"
	$(MAKE) -C ./enclave/

.PHONY: compiler-rt
compiler-rt:
	@echo
	@echo "Building the compiler"
	$(MAKE) -C ./rust-sgx-sdk/compiler-rt/ 2> /dev/null

.PHONY: clean
clean:
	@echo "Removing the compiled files"
	@rm -f $(Client_Name) $(Worker_Name) $(RustEnclave_Name) $(Signed_RustEnclave_Name) enclave/*_t.* worker/*_u.* lib/*.a bin/*.bin
	@echo "cargo clean and remove Cargo.lock in enclave directory"
	@cd enclave && cargo clean && rm -f Cargo.lock
	@echo "cargo clean and remove Cargo.lock in root directory"
	@cargo clean && rm -f Cargo.lock

mrenclave: $(Signed_Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) dump -enclave $(Signed_Enclave_Name) -dumpfile df.out && ./extract-identity < df.out && rm df.out

mrsigner: $(Signed_Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) dump -enclave $(Signed_Enclave_Name) -dumpfile df.out && ./extract-identity --mrsigner < df.out && rm df.out

.PHONY: identity
identity: mrenclave mrsigner

.PHONY: help
help:
	@echo "Available targets"
	@echo "  all     - builds all targets (default)"
	@echo "  worker  - builds the substraTEE-worker"
	@echo "  client  - builds the substraTEE-client"
	@echo ""
	@echo "  clean   - cleanup"
