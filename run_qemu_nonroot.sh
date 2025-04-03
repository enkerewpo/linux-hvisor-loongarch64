#!/bin/bash

# https://www.qemu.org/docs/master/system/loongarch/virt.html

KERNEL_PATH=nr_tmp/vmlinux

qemu-system-loongarch64 -machine virt -m 16G -cpu la464 \
    -smp 1 -kernel $KERNEL_PATH \
    --nographic \
    -serial mon:stdio
    
    # -device virtio-serial-pci,id=virtio-serial0 \
    # -chardev stdio,id=charconsole0 \
    # -device virtconsole,chardev=charconsole0,id=console0 