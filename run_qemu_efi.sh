#!/bin/bash

# https://www.qemu.org/docs/master/system/loongarch/virt.html

CHOSEN_ROOT=$(cat chosen_nonroot)
KERNEL_PATH=linux-${CHOSEN_ROOT}/arch/loongarch/boot/vmlinux.efi

# virt,dumpdtb=virt.dtb
# dtc -I dtb -O dts -o virt.dts virt.dtb

qemu-system-loongarch64 -m 16G -cpu la464 \
    -machine virt \
    -smp 1 -bios QEMU_EFI.fd -kernel $KERNEL_PATH \
    -append "root=/dev/ram rdinit=/init console=ttyS0,115200 loglevel=8 debug earlyprintk" \
    -serial mon:stdio \
    --nographic \
    -device igb,netdev=net0,bus=pcie.0,addr=0x6 \
    -netdev user,id=net0 \
    -device nvme,drive=nvme0,bus=pcie.0,addr=0x5,serial=1234567890 \
    -drive file=nvme_ext4.img,if=none,id=nvme0,format=raw