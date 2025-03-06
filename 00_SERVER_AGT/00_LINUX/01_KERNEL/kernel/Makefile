MODULE_NAME := nda-nfk
#SRC_NAME = nda_nfk
INSTALL_DIR = ../build

obj-m += $(MODULE_NAME).o

PRIVATE_KEY = ~/certs/priv.key
PUBLIC_KEY = ~/certs/pubkey.pem

KERNEL_VERSION=$(uname -r)

EXTRA_CFLAGS += -g

# source file
nda-nfk-objs :=	nda-nfk_main.o \
			libsrc/nd_nix_util_str.o \
			libsrc/nd_nix_rules.o \
			libsrc/nd_nix_log.o \
			nd_nix_nfm_sessions.o
			


all:	$(MODULE_NAME).ko $(MODULE_NAME).sym

$(MODULE_NAME).ko:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

$(MODULE_NAME).sym: $(MODULE_NAME).ko
	objcopy --only-keep-debug $(MODULE_NAME).ko $(MODULE_NAME).sym
	
#	/usr/src/kernels/$(shell uname -r)/scripts/sign-file sha512 $(PRIVATE_KEY) $(PUBLIC_KEY) nd_nix_nfm.ko

install:$(MODULE_NAME).ko $(MODULE_NAME).sym
	@if [ ! -d $(INSTALL_DIR) ]; then \
		echo "Creating $(INSTALL_DIR) directory"; \
		mkdir -p $(INSTALL_DIR); \
	fi
	install -m 664 $(MODULE_NAME).ko $(INSTALL_DIR)
	install -m 664 $(MODULE_NAME).sym $(INSTALL_DIR)


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f $(MODULE_NAME).sym
