# SPDX-License-Identifier: GPL-2.0-only

dtb-y = loongson-2k0500-ref.dtb loongson-2k1000-ref.dtb loongson-2k2000-ref.dtb
dtb-y += loongson-3a5000-hvisor-root.dtb loongson-3a5000-hvisor-nonroot.dtb
dtb-y += linux1.dtb linux2.dtb linux3.dtb

obj-$(CONFIG_BUILTIN_DTB)	+= $(addsuffix .dtb.o, $(CONFIG_BUILTIN_DTB_NAME))
