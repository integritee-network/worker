# helper script to update the files in rust-sgx-sdk to the lastest version

GIT = git
CP  = cp

REPO = https://github.com/baidu/rust-sgx-sdk.git
SDK_PATH_GIT = rust-sgx-sdk-github
SDK_PATH = rust-sgx-sdk
VERSION_FILE = rust-sgx-sdk/version
LOCAL_VERSION = $(shell cat $(VERSION_FILE))
COMMAND = git ls-remote $(REPO) HEAD | awk '{ print $$1 }'
REMOTE_VERSION = $(shell $(COMMAND))

# version vor sgx-sdk v1.1.1 release
VERSION111 = 66aaa2888992c63137e87adc688ddedab1181056

# update the SDK files
all: updatesdk

updatesdk:
# check for already updated version
ifneq ('$(VERSION111)','$(LOCAL_VERSION)')
	@echo Local version = $(LOCAL_VERSION)
	@echo sgxsdk v1.1.1 version = $(VERSION111)

	@rm -rf $(SDK_PATH_GIT)
	@$(GIT) clone $(REPO) $(SDK_PATH_GIT)
	@cd $(SDK_PATH_GIT) && $(GIT) checkout $(VERSION111) && cd ../
	rsync -a $(SDK_PATH_GIT)/edl $(SDK_PATH)
	rsync -a $(SDK_PATH_GIT)/common $(SDK_PATH)
	rsync -a $(SDK_PATH_GIT)/compiler-rt $(SDK_PATH)
	rm -rf $(SDK_PATH_GIT)
	@echo $(VERSION111) > $(VERSION_FILE)

endif
