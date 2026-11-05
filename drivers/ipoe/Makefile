obj-m += ipoe.o

# The netns_local bit (6.12) was renamed to netns_immutable (6.15), and
# stable kernels backport the rename (6.12.114+), so LINUX_VERSION_CODE
# alone cannot tell which one the headers provide. Probe the header.
IPOE_NETDEVICE_H := $(srctree)/include/linux/netdevice.h
ifneq ($(shell grep -q 'netns_immutable:1' $(IPOE_NETDEVICE_H) 2>/dev/null && echo y),)
ccflags-y += -DHAVE_NETNS_IMMUTABLE
else ifneq ($(shell grep -q 'netns_local:1' $(IPOE_NETDEVICE_H) 2>/dev/null && echo y),)
ccflags-y += -DHAVE_NETNS_LOCAL
endif

default:
	make -C $(KDIR) M=$(PWD) modules
