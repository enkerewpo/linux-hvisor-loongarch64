// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the interrupt descriptor management code. Detailed
 * information is available in Documentation/core-api/genericirq.rst
 *
 */
#include <linux/irq.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/maple_tree.h>
#include <linux/irqdomain.h>
#include <linux/sysfs.h>
#include <linux/string_choices.h>

#include "internals.h"

/*
 * lockdep: we want to handle all irq_desc locks as a single lock-class:
 */
static struct lock_class_key irq_desc_lock_class;

#if defined(CONFIG_SMP)
static int __init irq_affinity_setup(char *str)
{
	alloc_bootmem_cpumask_var(&irq_default_affinity);
	cpulist_parse(str, irq_default_affinity);
	/*
	 * Set at least the boot cpu. We don't want to end up with
	 * bugreports caused by random commandline masks
	 */
	cpumask_set_cpu(smp_processor_id(), irq_default_affinity);
	return 1;
}
__setup("irqaffinity=", irq_affinity_setup);

static void __init init_irq_default_affinity(void)
{
	if (!cpumask_available(irq_default_affinity))
		zalloc_cpumask_var(&irq_default_affinity, GFP_NOWAIT);
	if (cpumask_empty(irq_default_affinity))
		cpumask_setall(irq_default_affinity);
}
#else
static void __init init_irq_default_affinity(void)
{
}
#endif

#ifdef CONFIG_SMP
static int alloc_masks(struct irq_desc *desc, int node)
{
	if (!zalloc_cpumask_var_node(&desc->irq_common_data.affinity,
				     GFP_KERNEL, node))
		return -ENOMEM;

#ifdef CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK
	if (!zalloc_cpumask_var_node(&desc->irq_common_data.effective_affinity,
				     GFP_KERNEL, node)) {
		free_cpumask_var(desc->irq_common_data.affinity);
		return -ENOMEM;
	}
#endif

#ifdef CONFIG_GENERIC_PENDING_IRQ
	if (!zalloc_cpumask_var_node(&desc->pending_mask, GFP_KERNEL, node)) {
#ifdef CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK
		free_cpumask_var(desc->irq_common_data.effective_affinity);
#endif
		free_cpumask_var(desc->irq_common_data.affinity);
		return -ENOMEM;
	}
#endif
	return 0;
}

static void desc_smp_init(struct irq_desc *desc, int node,
			  const struct cpumask *affinity)
{
	if (!affinity)
		affinity = irq_default_affinity;
	cpumask_copy(desc->irq_common_data.affinity, affinity);

#ifdef CONFIG_GENERIC_PENDING_IRQ
	cpumask_clear(desc->pending_mask);
#endif
#ifdef CONFIG_NUMA
	desc->irq_common_data.node = node;
#endif
}

static void free_masks(struct irq_desc *desc)
{
#ifdef CONFIG_GENERIC_PENDING_IRQ
	free_cpumask_var(desc->pending_mask);
#endif
	free_cpumask_var(desc->irq_common_data.affinity);
#ifdef CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK
	free_cpumask_var(desc->irq_common_data.effective_affinity);
#endif
}

#else
static inline int alloc_masks(struct irq_desc *desc, int node)
{
	return 0;
}
static inline void desc_smp_init(struct irq_desc *desc, int node,
				 const struct cpumask *affinity)
{
}
static inline void free_masks(struct irq_desc *desc)
{
}
#endif

static void desc_set_defaults(unsigned int irq, struct irq_desc *desc, int node,
			      const struct cpumask *affinity,
			      struct module *owner)
{
	int cpu;

	desc->irq_common_data.handler_data = NULL;
	desc->irq_common_data.msi_desc = NULL;

	desc->irq_data.common = &desc->irq_common_data;
	desc->irq_data.irq = irq;
	desc->irq_data.chip = &no_irq_chip;
	desc->irq_data.chip_data = NULL;
	irq_settings_clr_and_set(desc, ~0, _IRQ_DEFAULT_INIT_FLAGS);
	irqd_set(&desc->irq_data, IRQD_IRQ_DISABLED);
	irqd_set(&desc->irq_data, IRQD_IRQ_MASKED);
	desc->handle_irq = handle_bad_irq;
	desc->depth = 1;
	desc->irq_count = 0;
	desc->irqs_unhandled = 0;
	desc->tot_count = 0;
	desc->name = NULL;
	desc->owner = owner;
	for_each_possible_cpu(cpu)
		*per_cpu_ptr(desc->kstat_irqs, cpu) = (struct irqstat){};
	desc_smp_init(desc, node, affinity);
}

static unsigned int nr_irqs = NR_IRQS;

/**
 * irq_get_nr_irqs() - Number of interrupts supported by the system.
 */
unsigned int irq_get_nr_irqs(void)
{
	return nr_irqs;
}
EXPORT_SYMBOL_GPL(irq_get_nr_irqs);

/**
 * irq_set_nr_irqs() - Set the number of interrupts supported by the system.
 * @nr: New number of interrupts.
 *
 * Return: @nr.
 */
unsigned int irq_set_nr_irqs(unsigned int nr)
{
	nr_irqs = nr;

	return nr;
}
EXPORT_SYMBOL_GPL(irq_set_nr_irqs);

static DEFINE_MUTEX(sparse_irq_lock);
static struct maple_tree sparse_irqs = MTREE_INIT_EXT(
	sparse_irqs,
	MT_FLAGS_ALLOC_RANGE | MT_FLAGS_LOCK_EXTERN | MT_FLAGS_USE_RCU,
	sparse_irq_lock);

static int irq_find_free_area(unsigned int from, unsigned int cnt)
{
	MA_STATE(mas, &sparse_irqs, 0, 0);

	if (mas_empty_area(&mas, from, MAX_SPARSE_IRQS, cnt))
		return -ENOSPC;
	return mas.index;
}

static unsigned int irq_find_at_or_after(unsigned int offset)
{
	unsigned long index = offset;
	struct irq_desc *desc;

	guard(rcu)();
	desc = mt_find(&sparse_irqs, &index, nr_irqs);

	return desc ? irq_desc_get_irq(desc) : nr_irqs;
}

static void irq_insert_desc(unsigned int irq, struct irq_desc *desc)
{
	MA_STATE(mas, &sparse_irqs, irq, irq);
	WARN_ON(mas_store_gfp(&mas, desc, GFP_KERNEL) != 0);
}

static void delete_irq_desc(unsigned int irq)
{
	MA_STATE(mas, &sparse_irqs, irq, irq);
	mas_erase(&mas);
}

#ifdef CONFIG_SPARSE_IRQ
static const struct kobj_type irq_kobj_type;
#endif

static int init_desc(struct irq_desc *desc, int irq, int node,
		     unsigned int flags, const struct cpumask *affinity,
		     struct module *owner)
{
	desc->kstat_irqs = alloc_percpu(struct irqstat);
	if (!desc->kstat_irqs)
		return -ENOMEM;

	if (alloc_masks(desc, node)) {
		free_percpu(desc->kstat_irqs);
		return -ENOMEM;
	}

	raw_spin_lock_init(&desc->lock);
	lockdep_set_class(&desc->lock, &irq_desc_lock_class);
	mutex_init(&desc->request_mutex);
	init_waitqueue_head(&desc->wait_for_threads);
	desc_set_defaults(irq, desc, node, affinity, owner);
	irqd_set(&desc->irq_data, flags);
	irq_resend_init(desc);
#ifdef CONFIG_SPARSE_IRQ
	kobject_init(&desc->kobj, &irq_kobj_type);
	init_rcu_head(&desc->rcu);
#endif

	return 0;
}

#ifdef CONFIG_SPARSE_IRQ

static void irq_kobj_release(struct kobject *kobj);

#ifdef CONFIG_SYSFS
static struct kobject *irq_kobj_base;

#define IRQ_ATTR_RO(_name) \
	static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

static ssize_t per_cpu_count_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct irq_desc *desc = container_of(kobj, struct irq_desc, kobj);
	ssize_t ret = 0;
	char *p = "";
	int cpu;

	for_each_possible_cpu(cpu) {
		unsigned int c = irq_desc_kstat_cpu(desc, cpu);

		ret += scnprintf(buf + ret, PAGE_SIZE - ret, "%s%u", p, c);
		p = ",";
	}

	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "\n");
	return ret;
}
IRQ_ATTR_RO(per_cpu_count);

static ssize_t chip_name_show(struct kobject *kobj, struct kobj_attribute *attr,
			      char *buf)
{
	struct irq_desc *desc = container_of(kobj, struct irq_desc, kobj);
	ssize_t ret = 0;

	raw_spin_lock_irq(&desc->lock);
	if (desc->irq_data.chip && desc->irq_data.chip->name) {
		ret = scnprintf(buf, PAGE_SIZE, "%s\n",
				desc->irq_data.chip->name);
	}
	raw_spin_unlock_irq(&desc->lock);

	return ret;
}
IRQ_ATTR_RO(chip_name);

static ssize_t hwirq_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	struct irq_desc *desc = container_of(kobj, struct irq_desc, kobj);
	ssize_t ret = 0;

	raw_spin_lock_irq(&desc->lock);
	if (desc->irq_data.domain)
		ret = sprintf(buf, "%lu\n", desc->irq_data.hwirq);
	raw_spin_unlock_irq(&desc->lock);

	return ret;
}
IRQ_ATTR_RO(hwirq);

static ssize_t type_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	struct irq_desc *desc = container_of(kobj, struct irq_desc, kobj);
	ssize_t ret = 0;

	raw_spin_lock_irq(&desc->lock);
	ret = sprintf(buf, "%s\n",
		      irqd_is_level_type(&desc->irq_data) ? "level" : "edge");
	raw_spin_unlock_irq(&desc->lock);

	return ret;
}
IRQ_ATTR_RO(type);

static ssize_t wakeup_show(struct kobject *kobj, struct kobj_attribute *attr,
			   char *buf)
{
	struct irq_desc *desc = container_of(kobj, struct irq_desc, kobj);
	ssize_t ret = 0;

	raw_spin_lock_irq(&desc->lock);
	ret = sprintf(
		buf, "%s\n",
		str_enabled_disabled(irqd_is_wakeup_set(&desc->irq_data)));
	raw_spin_unlock_irq(&desc->lock);

	return ret;
}
IRQ_ATTR_RO(wakeup);

static ssize_t name_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	struct irq_desc *desc = container_of(kobj, struct irq_desc, kobj);
	ssize_t ret = 0;

	raw_spin_lock_irq(&desc->lock);
	if (desc->name)
		ret = scnprintf(buf, PAGE_SIZE, "%s\n", desc->name);
	raw_spin_unlock_irq(&desc->lock);

	return ret;
}
IRQ_ATTR_RO(name);

static ssize_t actions_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	struct irq_desc *desc = container_of(kobj, struct irq_desc, kobj);
	struct irqaction *action;
	ssize_t ret = 0;
	char *p = "";

	raw_spin_lock_irq(&desc->lock);
	for_each_action_of_desc(desc, action)
	{
		ret += scnprintf(buf + ret, PAGE_SIZE - ret, "%s%s", p,
				 action->name);
		p = ",";
	}
	raw_spin_unlock_irq(&desc->lock);

	if (ret)
		ret += scnprintf(buf + ret, PAGE_SIZE - ret, "\n");

	return ret;
}
IRQ_ATTR_RO(actions);

static struct attribute *irq_attrs[] = {
	&per_cpu_count_attr.attr, &chip_name_attr.attr,
	&hwirq_attr.attr,	  &type_attr.attr,
	&wakeup_attr.attr,	  &name_attr.attr,
	&actions_attr.attr,	  NULL
};
ATTRIBUTE_GROUPS(irq);

static const struct kobj_type irq_kobj_type = {
	.release = irq_kobj_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = irq_groups,
};

static void irq_sysfs_add(int irq, struct irq_desc *desc)
{
	if (irq_kobj_base) {
		/*
		 * Continue even in case of failure as this is nothing
		 * crucial and failures in the late irq_sysfs_init()
		 * cannot be rolled back.
		 */
		if (kobject_add(&desc->kobj, irq_kobj_base, "%d", irq))
			pr_warn("Failed to add kobject for irq %d\n", irq);
		else
			desc->istate |= IRQS_SYSFS;
	}
}

static void irq_sysfs_del(struct irq_desc *desc)
{
	/*
	 * Only invoke kobject_del() when kobject_add() was successfully
	 * invoked for the descriptor. This covers both early boot, where
	 * sysfs is not initialized yet, and the case of a failed
	 * kobject_add() invocation.
	 */
	if (desc->istate & IRQS_SYSFS)
		kobject_del(&desc->kobj);
}

static int __init irq_sysfs_init(void)
{
	struct irq_desc *desc;
	int irq;

	/* Prevent concurrent irq alloc/free */
	irq_lock_sparse();

	irq_kobj_base = kobject_create_and_add("irq", kernel_kobj);
	if (!irq_kobj_base) {
		irq_unlock_sparse();
		return -ENOMEM;
	}

	/* Add the already allocated interrupts */
	for_each_irq_desc(irq, desc) irq_sysfs_add(irq, desc);
	irq_unlock_sparse();

	return 0;
}
postcore_initcall(irq_sysfs_init);

#else /* !CONFIG_SYSFS */

static const struct kobj_type irq_kobj_type = {
	.release = irq_kobj_release,
};

static void irq_sysfs_add(int irq, struct irq_desc *desc)
{
}
static void irq_sysfs_del(struct irq_desc *desc)
{
}

#endif /* CONFIG_SYSFS */

struct irq_desc *irq_to_desc(unsigned int irq)
{
	return mtree_load(&sparse_irqs, irq);
}
#ifdef CONFIG_KVM_BOOK3S_64_HV_MODULE
EXPORT_SYMBOL_GPL(irq_to_desc);
#endif

void irq_lock_sparse(void)
{
	mutex_lock(&sparse_irq_lock);
}

void irq_unlock_sparse(void)
{
	mutex_unlock(&sparse_irq_lock);
}

static struct irq_desc *alloc_desc(int irq, int node, unsigned int flags,
				   const struct cpumask *affinity,
				   struct module *owner)
{
	struct irq_desc *desc;
	int ret;

	desc = kzalloc_node(sizeof(*desc), GFP_KERNEL, node);
	if (!desc)
		return NULL;

	ret = init_desc(desc, irq, node, flags, affinity, owner);
	if (unlikely(ret)) {
		kfree(desc);
		return NULL;
	}

	return desc;
}

static void irq_kobj_release(struct kobject *kobj)
{
	struct irq_desc *desc = container_of(kobj, struct irq_desc, kobj);

	free_masks(desc);
	free_percpu(desc->kstat_irqs);
	kfree(desc);
}

static void delayed_free_desc(struct rcu_head *rhp)
{
	struct irq_desc *desc = container_of(rhp, struct irq_desc, rcu);

	kobject_put(&desc->kobj);
}

static void free_desc(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	irq_remove_debugfs_entry(desc);
	unregister_irq_proc(irq, desc);

	/*
	 * sparse_irq_lock protects also show_interrupts() and
	 * kstat_irq_usr(). Once we deleted the descriptor from the
	 * sparse tree we can free it. Access in proc will fail to
	 * lookup the descriptor.
	 *
	 * The sysfs entry must be serialized against a concurrent
	 * irq_sysfs_init() as well.
	 */
	irq_sysfs_del(desc);
	delete_irq_desc(irq);

	/*
	 * We free the descriptor, masks and stat fields via RCU. That
	 * allows demultiplex interrupts to do rcu based management of
	 * the child interrupts.
	 * This also allows us to use rcu in kstat_irqs_usr().
	 */
	call_rcu(&desc->rcu, delayed_free_desc);
}

static int alloc_descs(unsigned int start, unsigned int cnt, int node,
		       const struct irq_affinity_desc *affinity,
		       struct module *owner)
{
	struct irq_desc *desc;
	int i;

	/* Validate affinity mask(s) */
	if (affinity) {
		for (i = 0; i < cnt; i++) {
			if (cpumask_empty(&affinity[i].mask))
				return -EINVAL;
		}
	}

	for (i = 0; i < cnt; i++) {
		const struct cpumask *mask = NULL;
		unsigned int flags = 0;

		if (affinity) {
			if (affinity->is_managed) {
				flags = IRQD_AFFINITY_MANAGED |
					IRQD_MANAGED_SHUTDOWN;
			}
			flags |= IRQD_AFFINITY_SET;
			mask = &affinity->mask;
			node = cpu_to_node(cpumask_first(mask));
			affinity++;
		}

		desc = alloc_desc(start + i, node, flags, mask, owner);
		if (!desc)
			goto err;
		irq_insert_desc(start + i, desc);
		irq_sysfs_add(start + i, desc);
		irq_add_debugfs_entry(start + i, desc);
	}
	return start;

err:
	for (i--; i >= 0; i--)
		free_desc(start + i);
	return -ENOMEM;
}

static int irq_expand_nr_irqs(unsigned int nr)
{
	if (nr > MAX_SPARSE_IRQS)
		return -ENOMEM;
	nr_irqs = nr;
	return 0;
}

int __init early_irq_init(void)
{
	int i, initcnt, node = first_online_node;
	struct irq_desc *desc;

	init_irq_default_affinity();

	/* Let arch update nr_irqs and return the nr of preallocated irqs */
	initcnt = arch_probe_nr_irqs();
	printk(KERN_INFO "NR_IRQS: %d, nr_irqs: %d, preallocated irqs: %d\n",
	       NR_IRQS, nr_irqs, initcnt);

	if (WARN_ON(nr_irqs > MAX_SPARSE_IRQS))
		nr_irqs = MAX_SPARSE_IRQS;

	if (WARN_ON(initcnt > MAX_SPARSE_IRQS))
		initcnt = MAX_SPARSE_IRQS;

	if (initcnt > nr_irqs)
		nr_irqs = initcnt;

	for (i = 0; i < initcnt; i++) {
		desc = alloc_desc(i, node, 0, NULL, NULL);
		irq_insert_desc(i, desc);
	}
	return arch_early_irq_init();
}

#else /* !CONFIG_SPARSE_IRQ */

struct irq_desc irq_desc
	[NR_IRQS] __cacheline_aligned_in_smp = { [0 ... NR_IRQS - 1] = {
							 .handle_irq =
								 handle_bad_irq,
							 .depth = 1,
							 .lock = __RAW_SPIN_LOCK_UNLOCKED(
								 irq_desc->lock),
						 } };

int __init early_irq_init(void)
{
	int count, i, node = first_online_node;
	int ret;

	init_irq_default_affinity();

	printk(KERN_INFO "NR_IRQS: %d\n", NR_IRQS);

	count = ARRAY_SIZE(irq_desc);

	for (i = 0; i < count; i++) {
		ret = init_desc(irq_desc + i, i, node, 0, NULL, NULL);
		if (unlikely(ret))
			goto __free_desc_res;
	}

	return arch_early_irq_init();

__free_desc_res:
	while (--i >= 0) {
		free_masks(irq_desc + i);
		free_percpu(irq_desc[i].kstat_irqs);
	}

	return ret;
}

struct irq_desc *irq_to_desc(unsigned int irq)
{
	return (irq < NR_IRQS) ? irq_desc + irq : NULL;
}
EXPORT_SYMBOL(irq_to_desc);

static void free_desc(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	unsigned long flags;

	raw_spin_lock_irqsave(&desc->lock, flags);
	desc_set_defaults(irq, desc, irq_desc_get_node(desc), NULL, NULL);
	raw_spin_unlock_irqrestore(&desc->lock, flags);
	delete_irq_desc(irq);
}

static inline int alloc_descs(unsigned int start, unsigned int cnt, int node,
			      const struct irq_affinity_desc *affinity,
			      struct module *owner)
{
	u32 i;

	for (i = 0; i < cnt; i++) {
		struct irq_desc *desc = irq_to_desc(start + i);

		desc->owner = owner;
		irq_insert_desc(start + i, desc);
	}
	return start;
}

static int irq_expand_nr_irqs(unsigned int nr)
{
	return -ENOMEM;
}

void irq_mark_irq(unsigned int irq)
{
	mutex_lock(&sparse_irq_lock);
	irq_insert_desc(irq, irq_desc + irq);
	mutex_unlock(&sparse_irq_lock);
}

#ifdef CONFIG_GENERIC_IRQ_LEGACY
void irq_init_desc(unsigned int irq)
{
	free_desc(irq);
}
#endif

#endif /* !CONFIG_SPARSE_IRQ */

int handle_irq_desc(struct irq_desc *desc)
{
	struct irq_data *data;

	if (!desc)
		return -EINVAL;

	data = irq_desc_get_irq_data(desc);

	// if domain name != CPUINTC, print the domain name
	// if (!(strcmp(desc->irq_data.domain->name, "CPUINTC") == 0 || data->irq == 17 || data->hwirq == 11)) {
	// 	pr_info("wheatfox: handle_irq_desc, domain name=%s, data->hwirq=%d, data->irq=%d, handler=0x%px\n",
	// 			desc->irq_data.domain->name, (int)data->hwirq, (int)data->irq, desc->handle_irq);
	// }

	if (WARN_ON_ONCE(!in_hardirq() && handle_enforce_irqctx(data)))
		return -EPERM;

	generic_handle_irq_desc(desc);
	return 0;
}

/**
 * generic_handle_irq - Invoke the handler for a particular irq
 * @irq:	The irq number to handle
 *
 * Returns:	0 on success, or -EINVAL if conversion has failed
 *
 * 		This function must be called from an IRQ context with irq regs
 * 		initialized.
  */
int generic_handle_irq(unsigned int irq)
{
	return handle_irq_desc(irq_to_desc(irq));
}
EXPORT_SYMBOL_GPL(generic_handle_irq);

/**
 * generic_handle_irq_safe - Invoke the handler for a particular irq from any
 *			     context.
 * @irq:	The irq number to handle
 *
 * Returns:	0 on success, a negative value on error.
 *
 * This function can be called from any context (IRQ or process context). It
 * will report an error if not invoked from IRQ context and the irq has been
 * marked to enforce IRQ-context only.
 */
int generic_handle_irq_safe(unsigned int irq)
{
	unsigned long flags;
	int ret;

	local_irq_save(flags);
	ret = handle_irq_desc(irq_to_desc(irq));
	local_irq_restore(flags);
	return ret;
}
EXPORT_SYMBOL_GPL(generic_handle_irq_safe);

#ifdef CONFIG_IRQ_DOMAIN
/**
 * generic_handle_domain_irq - Invoke the handler for a HW irq belonging
 *                             to a domain.
 * @domain:	The domain where to perform the lookup
 * @hwirq:	The HW irq number to convert to a logical one
 *
 * Returns:	0 on success, or -EINVAL if conversion has failed
 *
 * 		This function must be called from an IRQ context with irq regs
 * 		initialized.
 */
int generic_handle_domain_irq(struct irq_domain *domain, unsigned int hwirq)
{
	// if (hwirq >= 64) {
	// 	pr_info("wheatfox: generic_handle_domain_irq, msi, hwirq=%d\n",
	// 		hwirq);
	// }
	struct irq_desc *desc = irq_resolve_mapping(domain, hwirq);
	// if (desc) {
	// 	pr_info("wheatfox: generic_handle_domain_irq, domain name=%s, desc->irq_data.irq = %d, desc->irq_data.hwirq = %d, addr of desc->handle_irq = %px\n",
	// 		domain->name, desc->irq_data.irq, (int)desc->irq_data.hwirq,
	// 		desc->handle_irq);
	// } else {
	// 	pr_info("wheatfox: generic_handle_domain_irq, desc is NULL, hwirq=%d\n",
	// 		hwirq);
	// }
	return handle_irq_desc(desc);
}
EXPORT_SYMBOL_GPL(generic_handle_domain_irq);

/**
 * generic_handle_irq_safe - Invoke the handler for a HW irq belonging
 *			     to a domain from any context.
 * @domain:	The domain where to perform the lookup
 * @hwirq:	The HW irq number to convert to a logical one
 *
 * Returns:	0 on success, a negative value on error.
 *
 * This function can be called from any context (IRQ or process
 * context). If the interrupt is marked as 'enforce IRQ-context only' then
 * the function must be invoked from hard interrupt context.
 */
int generic_handle_domain_irq_safe(struct irq_domain *domain,
				   unsigned int hwirq)
{
	unsigned long flags;
	int ret;

	local_irq_save(flags);
	ret = handle_irq_desc(irq_resolve_mapping(domain, hwirq));
	local_irq_restore(flags);
	return ret;
}
EXPORT_SYMBOL_GPL(generic_handle_domain_irq_safe);

/**
 * generic_handle_domain_nmi - Invoke the handler for a HW nmi belonging
 *                             to a domain.
 * @domain:	The domain where to perform the lookup
 * @hwirq:	The HW irq number to convert to a logical one
 *
 * Returns:	0 on success, or -EINVAL if conversion has failed
 *
 * 		This function must be called from an NMI context with irq regs
 * 		initialized.
 **/
int generic_handle_domain_nmi(struct irq_domain *domain, unsigned int hwirq)
{
	WARN_ON_ONCE(!in_nmi());
	return handle_irq_desc(irq_resolve_mapping(domain, hwirq));
}
#endif

/* Dynamic interrupt handling */

/**
 * irq_free_descs - free irq descriptors
 * @from:	Start of descriptor range
 * @cnt:	Number of consecutive irqs to free
 */
void irq_free_descs(unsigned int from, unsigned int cnt)
{
	int i;

	if (from >= nr_irqs || (from + cnt) > nr_irqs)
		return;

	mutex_lock(&sparse_irq_lock);
	for (i = 0; i < cnt; i++)
		free_desc(from + i);

	mutex_unlock(&sparse_irq_lock);
}
EXPORT_SYMBOL_GPL(irq_free_descs);

/**
 * __irq_alloc_descs - allocate and initialize a range of irq descriptors
 * @irq:	Allocate for specific irq number if irq >= 0
 * @from:	Start the search from this irq number
 * @cnt:	Number of consecutive irqs to allocate.
 * @node:	Preferred node on which the irq descriptor should be allocated
 * @owner:	Owning module (can be NULL)
 * @affinity:	Optional pointer to an affinity mask array of size @cnt which
 *		hints where the irq descriptors should be allocated and which
 *		default affinities to use
 *
 * Returns the first irq number or error code
 */
int __ref __irq_alloc_descs(int irq, unsigned int from, unsigned int cnt,
			    int node, struct module *owner,
			    const struct irq_affinity_desc *affinity)
{
	int start, ret;

	if (!cnt)
		return -EINVAL;

	if (irq >= 0) {
		if (from > irq)
			return -EINVAL;
		from = irq;
	} else {
		/*
		 * For interrupts which are freely allocated the
		 * architecture can force a lower bound to the @from
		 * argument. x86 uses this to exclude the GSI space.
		 */
		from = arch_dynirq_lower_bound(from);
	}

	mutex_lock(&sparse_irq_lock);

	start = irq_find_free_area(from, cnt);
	ret = -EEXIST;
	if (irq >= 0 && start != irq)
		goto unlock;

	if (start + cnt > nr_irqs) {
		ret = irq_expand_nr_irqs(start + cnt);
		if (ret)
			goto unlock;
	}
	ret = alloc_descs(start, cnt, node, affinity, owner);
unlock:
	mutex_unlock(&sparse_irq_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(__irq_alloc_descs);

/**
 * irq_get_next_irq - get next allocated irq number
 * @offset:	where to start the search
 *
 * Returns next irq number after offset or nr_irqs if none is found.
 */
unsigned int irq_get_next_irq(unsigned int offset)
{
	return irq_find_at_or_after(offset);
}

struct irq_desc *__irq_get_desc_lock(unsigned int irq, unsigned long *flags,
				     bool bus, unsigned int check)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (desc) {
		if (check & _IRQ_DESC_CHECK) {
			if ((check & _IRQ_DESC_PERCPU) &&
			    !irq_settings_is_per_cpu_devid(desc))
				return NULL;

			if (!(check & _IRQ_DESC_PERCPU) &&
			    irq_settings_is_per_cpu_devid(desc))
				return NULL;
		}

		if (bus)
			chip_bus_lock(desc);
		raw_spin_lock_irqsave(&desc->lock, *flags);
	}
	return desc;
}

void __irq_put_desc_unlock(struct irq_desc *desc, unsigned long flags, bool bus)
	__releases(&desc->lock)
{
	raw_spin_unlock_irqrestore(&desc->lock, flags);
	if (bus)
		chip_bus_sync_unlock(desc);
}

int irq_set_percpu_devid_partition(unsigned int irq,
				   const struct cpumask *affinity)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc || desc->percpu_enabled)
		return -EINVAL;

	desc->percpu_enabled =
		kzalloc(sizeof(*desc->percpu_enabled), GFP_KERNEL);

	if (!desc->percpu_enabled)
		return -ENOMEM;

	desc->percpu_affinity = affinity ?: cpu_possible_mask;

	irq_set_percpu_devid_flags(irq);
	return 0;
}

int irq_set_percpu_devid(unsigned int irq)
{
	return irq_set_percpu_devid_partition(irq, NULL);
}

int irq_get_percpu_devid_partition(unsigned int irq, struct cpumask *affinity)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc || !desc->percpu_enabled)
		return -EINVAL;

	if (affinity)
		cpumask_copy(affinity, desc->percpu_affinity);

	return 0;
}
EXPORT_SYMBOL_GPL(irq_get_percpu_devid_partition);

void kstat_incr_irq_this_cpu(unsigned int irq)
{
	kstat_incr_irqs_this_cpu(irq_to_desc(irq));
}

/**
 * kstat_irqs_cpu - Get the statistics for an interrupt on a cpu
 * @irq:	The interrupt number
 * @cpu:	The cpu number
 *
 * Returns the sum of interrupt counts on @cpu since boot for
 * @irq. The caller must ensure that the interrupt is not removed
 * concurrently.
 */
unsigned int kstat_irqs_cpu(unsigned int irq, int cpu)
{
	struct irq_desc *desc = irq_to_desc(irq);

	return desc && desc->kstat_irqs ? per_cpu(desc->kstat_irqs->cnt, cpu) :
					  0;
}

unsigned int kstat_irqs_desc(struct irq_desc *desc,
			     const struct cpumask *cpumask)
{
	unsigned int sum = 0;
	int cpu;

	if (!irq_settings_is_per_cpu_devid(desc) &&
	    !irq_settings_is_per_cpu(desc) && !irq_is_nmi(desc))
		return data_race(desc->tot_count);

	for_each_cpu(cpu, cpumask)
		sum += data_race(per_cpu(desc->kstat_irqs->cnt, cpu));
	return sum;
}

static unsigned int kstat_irqs(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc || !desc->kstat_irqs)
		return 0;
	return kstat_irqs_desc(desc, cpu_possible_mask);
}

#ifdef CONFIG_GENERIC_IRQ_STAT_SNAPSHOT

void kstat_snapshot_irqs(void)
{
	struct irq_desc *desc;
	unsigned int irq;

	for_each_irq_desc(irq, desc)
	{
		if (!desc->kstat_irqs)
			continue;
		this_cpu_write(desc->kstat_irqs->ref,
			       this_cpu_read(desc->kstat_irqs->cnt));
	}
}

unsigned int kstat_get_irq_since_snapshot(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc || !desc->kstat_irqs)
		return 0;
	return this_cpu_read(desc->kstat_irqs->cnt) -
	       this_cpu_read(desc->kstat_irqs->ref);
}

#endif

/**
 * kstat_irqs_usr - Get the statistics for an interrupt from thread context
 * @irq:	The interrupt number
 *
 * Returns the sum of interrupt counts on all cpus since boot for @irq.
 *
 * It uses rcu to protect the access since a concurrent removal of an
 * interrupt descriptor is observing an rcu grace period before
 * delayed_free_desc()/irq_kobj_release().
 */
unsigned int kstat_irqs_usr(unsigned int irq)
{
	unsigned int sum;

	rcu_read_lock();
	sum = kstat_irqs(irq);
	rcu_read_unlock();
	return sum;
}

#ifdef CONFIG_LOCKDEP
void __irq_set_lockdep_class(unsigned int irq,
			     struct lock_class_key *lock_class,
			     struct lock_class_key *request_class)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (desc) {
		lockdep_set_class(&desc->lock, lock_class);
		lockdep_set_class(&desc->request_mutex, request_class);
	}
}
EXPORT_SYMBOL_GPL(__irq_set_lockdep_class);
#endif
