obj-m += vlan_mon.o
ccflags-y += -DACCEL_PPP_VERSION=\"$(ACCEL_PPP_VERSION)\"

default:
	make -C $(KDIR) M=$(PWD) modules
