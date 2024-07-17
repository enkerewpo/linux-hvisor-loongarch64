NPROC = 16

GNU_CROSS_COMPILER_PREFIX := loongarch64-unknown-linux-gnu-
GNU_CROSS_COMPILER_GCC    := $(GNU_CROSS_COMPILER_PREFIX)gcc
GNU_STRIP := $(GNU_CROSS_COMPILER_PREFIX)strip


ARCH = loongarch64
QEMU = qemu-system-loongarch64 # with vga
CROSS_COMPILE = loongarch64-unknown-linux-gnu-
CROSS_GDB = loongarch64-linux-gnu-gdb
CC = loongarch64-unknown-linux-gnu-gcc
CXX = loongarch64-unknown-linux-gnu-g++
LD = loongarch64-unknown-linux-gnu-ld
AR = loongarch64-unknown-linux-gnu-ar
OBJCOPY = rust-objcopy --binary-architecture=$(ARCH)
OBJDUMP = rust-objdump
READELF = loongarch64-unknown-linux-gnu-readelf
MODE = debug

# ROOTFS STUFF
TMP_ROOTFS_OUTPUT := ./output

all:
# pack rootfs.cpio.gz from built busybox
	rm -rf $(TMP_ROOTFS_OUTPUT)
	mkdir -p $(TMP_ROOTFS_OUTPUT)

# pack $(TMP_ROOTFS_OUTPUT) to ./rootfs.cpio.gz
	mkdir -p $(TMP_ROOTFS_OUTPUT)/bin
	mkdir -p $(TMP_ROOTFS_OUTPUT)/sbin
	mkdir -p $(TMP_ROOTFS_OUTPUT)/usr/bin
	mkdir -p $(TMP_ROOTFS_OUTPUT)/usr/sbin
	mkdir -p $(TMP_ROOTFS_OUTPUT)/usr/lib
	mkdir -p $(TMP_ROOTFS_OUTPUT)/usr/lib64
	mkdir -p $(TMP_ROOTFS_OUTPUT)/usr/include
	mkdir -p $(TMP_ROOTFS_OUTPUT)/usr/share
	mkdir -p $(TMP_ROOTFS_OUTPUT)/usr/local
	mkdir -p $(TMP_ROOTFS_OUTPUT)/etc
	mkdir -p $(TMP_ROOTFS_OUTPUT)/var
	mkdir -p $(TMP_ROOTFS_OUTPUT)/proc
	mkdir -p $(TMP_ROOTFS_OUTPUT)/sys
	mkdir -p $(TMP_ROOTFS_OUTPUT)/tmp
	mkdir -p $(TMP_ROOTFS_OUTPUT)/root
	mkdir -p $(TMP_ROOTFS_OUTPUT)/run
	mkdir -p $(TMP_ROOTFS_OUTPUT)/proc/self
	touch $(TMP_ROOTFS_OUTPUT)/proc/self/auxv
	mkdir -p $(TMP_ROOTFS_OUTPUT)/dev
	cd $(TMP_ROOTFS_OUTPUT)/dev && sudo mknod -m 666 null c 1 3
	cd $(TMP_ROOTFS_OUTPUT)/dev && sudo mknod -m 666 console c 5 1
	cp busybox/busybox $(TMP_ROOTFS_OUTPUT)/bin
# bin
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/init
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/sh
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/ls
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/cat
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/mkdir
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/rm
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/mv
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/cp
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/echo
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/ln
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/ps
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/kill
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/mount
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/umount
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/df
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/du
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/clear
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/touch
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/which
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/whoami
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/who
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/uptime
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/chmod
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/hostname
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/date
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/true
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/false
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/seq
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/awk
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/bin/top
# sbin
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/sbin/init
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/sbin/halt
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/sbin/reboot
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/sbin/poweroff
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/sbin/swapon
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/sbin/swapoff
	ln -s /bin/busybox $(TMP_ROOTFS_OUTPUT)/sbin/chroot
# overlay
# copy all files in overlay to rootfs
	cp -r overlay/* $(TMP_ROOTFS_OUTPUT)
	chmod +x $(TMP_ROOTFS_OUTPUT)/etc/init.d/rcS

	cd $(TMP_ROOTFS_OUTPUT) && find . | cpio -o -H newc | gzip > ../rootfs.cpio.gz

# http://ftp.loongnix.cn/toolchain/gcc/release/loongarch/gcc8/toolchain-loongarch64-linux-gnu-cross-830-rc1.0-2022-04-22.tar.xz
busybox: .PHONY
	cp config/config.gnu.novec busybox/.config
	make -C busybox -j $(NPROC)

clean: .PHONY
	make -C busybox clean 


.PHONY:

