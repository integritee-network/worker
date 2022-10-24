# helper script to update the files in rust-sgx-sdk to the lastest version

GIT = git
CP  = cp

REPO = https://github.com/apache/incubator-teaclave-sgx-sdk
SDK_PATH_GIT = rust-sgx-sdk-github
SDK_PATH = rust-sgx-sdk
VERSION_FILE = rust-sgx-sdk/version
LOCAL_VERSION = $(shell cat $(VERSION_FILE))
COMMAND = git ls-remote $(REPO) HEAD | awk '{ print $$1 }'
REMOTE_VERSION = $(shell $(COMMAND))
# or specify the exact hash if you need a non-default branch / tag / commit etc.
#REMOTE_VERSION = 9c1bbd52f188f600a212b57c916124245da1b7fd

# update the SDK files
all: updatesdk

updatesdk:
# check for already updated version
ifneq ('$(LOCAL_VERSION)','$(REMOTE_VERSION)')
	@echo Local version = $(LOCAL_VERSION)
	@echo Remote version = $(REMOTE_VERSION)

	@rm -rf $(SDK_PATH_GIT)
	@$(GIT) clone $(REPO) $(SDK_PATH_GIT)
	@$(GIT) -C  $(SDK_PATH_GIT) checkout $(REMOTE_VERSION)
	rsync -a $(SDK_PATH_GIT)/edl $(SDK_PATH)
	rsync -a $(SDK_PATH_GIT)/common $(SDK_PATH)
	rm -rf $(SDK_PATH_GIT)
	@echo $(REMOTE_VERSION) > $(VERSION_FILE)

endif
