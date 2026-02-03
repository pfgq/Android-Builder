/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2007 Alan Stern
 * Copyright (C) IBM Corporation, 2009
 * Copyright (C) 2009, Frederic Weisbecker <fweisbec@gmail.com>
 */

#include <linux/irqflags.h>
#include <linux/kallsyms.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <linux/kdebug.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/bug.h>

#include <linux/hw_breakpoint.h>

/* ===== hwhook gate (新增) ===== */
struct mutex hwhook_gate_lock;
EXPORT_SYMBOL_GPL(hwhook_gate_lock);
/* ============================== */

/*
 * Constraints data
 */
struct bp_cpuinfo {
	unsigned int cpu_pinned;
	unsigned int *tsk_pinned;
	unsigned int flexible;
};

static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
static int nr_slots[TYPE_MAX];

static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
{
	return per_cpu_ptr(bp_cpuinfo + type, cpu);
}

static LIST_HEAD(bp_task_head);
static int constraints_initialized;

struct bp_busy_slots {
	unsigned int pinned;
	unsigned int flexible;
};

static DEFINE_MUTEX(nr_bp_mutex);

__weak int hw_breakpoint_weight(struct perf_event *bp)
{
	return 1;
}

static inline enum bp_type_idx find_slot_idx(u64 bp_type)
{
	if (bp_type & HW_BREAKPOINT_RW)
		return TYPE_DATA;
	return TYPE_INST;
}

static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
{
	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
	int i;

	for (i = nr_slots[type] - 1; i >= 0; i--) {
		if (tsk_pinned[i] > 0)
			return i + 1;
	}
	return 0;
}

static int task_bp_pinned(int cpu, struct perf_event *bp, enum bp_type_idx type)
{
	struct task_struct *tsk = bp->hw.target;
	struct perf_event *iter;
	int count = 0;

	list_for_each_entry(iter, &bp_task_head, hw.bp_list) {
		if (iter->hw.target == tsk &&
		    find_slot_idx(iter->attr.bp_type) == type &&
		    (iter->cpu < 0 || cpu == iter->cpu))
			count += hw_breakpoint_weight(iter);
	}
	return count;
}

static const struct cpumask *cpumask_of_bp(struct perf_event *bp)
{
	if (bp->cpu >= 0)
		return cpumask_of(bp->cpu);
	return cpu_possible_mask;
}

static void fetch_bp_busy_slots(struct bp_busy_slots *slots,
				struct perf_event *bp,
				enum bp_type_idx type)
{
	const struct cpumask *cpumask = cpumask_of_bp(bp);
	int cpu;

	for_each_cpu(cpu, cpumask) {
		struct bp_cpuinfo *info = get_bp_info(cpu, type);
		int nr;

		nr = info->cpu_pinned;
		if (!bp->hw.target)
			nr += max_task_bp_pinned(cpu, type);
		else
			nr += task_bp_pinned(cpu, bp, type);

		if (nr > slots->pinned)
			slots->pinned = nr;

		nr = info->flexible;
		if (nr > slots->flexible)
			slots->flexible = nr;
	}
}

static void fetch_this_slot(struct bp_busy_slots *slots, int weight)
{
	slots->pinned += weight;
}

static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
				enum bp_type_idx type, int weight)
{
	unsigned int *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
	int old_idx, new_idx;

	old_idx = task_bp_pinned(cpu, bp, type) - 1;
	new_idx = old_idx + weight;

	if (old_idx >= 0)
		tsk_pinned[old_idx]--;
	if (new_idx >= 0)
		tsk_pinned[new_idx]++;
}

static void toggle_bp_slot(struct perf_event *bp, bool enable,
			   enum bp_type_idx type, int weight)
{
	const struct cpumask *cpumask = cpumask_of_bp(bp);
	int cpu;

	if (!enable)
		weight = -weight;

	if (!bp->hw.target) {
		get_bp_info(bp->cpu, type)->cpu_pinned += weight;
		return;
	}

	for_each_cpu(cpu, cpumask)
		toggle_bp_task_slot(bp, cpu, type, weight);

	if (enable)
		list_add_tail(&bp->hw.bp_list, &bp_task_head);
	else
		list_del(&bp->hw.bp_list);
}

__weak void arch_unregister_hw_breakpoint(struct perf_event *bp) { }

static int __reserve_bp_slot(struct perf_event *bp, u64 bp_type)
{
	struct bp_busy_slots slots = { 0 };
	enum bp_type_idx type;
	int weight;

	if (!constraints_initialized)
		return -ENOMEM;

	if (bp_type == HW_BREAKPOINT_EMPTY ||
	    bp_type == HW_BREAKPOINT_INVALID)
		return -EINVAL;

	type = find_slot_idx(bp_type);
	weight = hw_breakpoint_weight(bp);

	fetch_bp_busy_slots(&slots, bp, type);
	fetch_this_slot(&slots, weight);

	if (slots.pinned + (!!slots.flexible) > nr_slots[type])
		return -ENOSPC;

	toggle_bp_slot(bp, true, type, weight);
	return 0;
}

int reserve_bp_slot(struct perf_event *bp)
{
	int ret;

	mutex_lock(&nr_bp_mutex);
	ret = __reserve_bp_slot(bp, bp->attr.bp_type);
	mutex_unlock(&nr_bp_mutex);

	return ret;
}

static void __release_bp_slot(struct perf_event *bp, u64 bp_type)
{
	enum bp_type_idx type = find_slot_idx(bp_type);
	int weight = hw_breakpoint_weight(bp);

	toggle_bp_slot(bp, false, type, weight);
}

void release_bp_slot(struct perf_event *bp)
{
	mutex_lock(&nr_bp_mutex);
	arch_unregister_hw_breakpoint(bp);
	__release_bp_slot(bp, bp->attr.bp_type);
	mutex_unlock(&nr_bp_mutex);
}

int register_perf_hw_breakpoint(struct perf_event *bp)
{
	struct arch_hw_breakpoint hw = { };
	int err;

	err = reserve_bp_slot(bp);
	if (err)
		return err;

	err = hw_breakpoint_parse(bp, &bp->attr, &hw);
	if (err) {
		release_bp_slot(bp);
		return err;
	}

	bp->hw.info = hw;
	return 0;
}

/* ===== 用户态 HWBP 注册（加 gate） ===== */
struct perf_event *
register_user_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context,
			    struct task_struct *tsk)
{
	if (!mutex_is_locked(&hwhook_gate_lock))
		return ERR_PTR(-EPERM);

	return perf_event_create_kernel_counter(attr, -1, tsk,
						triggered, context);
}
EXPORT_SYMBOL_GPL(register_user_hw_breakpoint);
/* ======================================== */

int __init init_hw_breakpoint(void)
{
	int cpu, err_cpu;
	int i;

	/* ===== gate mutex 初始化（新增） ===== */
	mutex_init(&hwhook_gate_lock);
	/* ===================================== */

	for (i = 0; i < TYPE_MAX; i++)
		nr_slots[i] = hw_breakpoint_slots(i);

	for_each_possible_cpu(cpu) {
		for (i = 0; i < TYPE_MAX; i++) {
			struct bp_cpuinfo *info = get_bp_info(cpu, i);

			info->tsk_pinned = kcalloc(nr_slots[i],
						   sizeof(int), GFP_KERNEL);
			if (!info->tsk_pinned)
				goto err_alloc;
		}
	}

	constraints_initialized = 1;
	perf_pmu_register(&perf_breakpoint,
			  "breakpoint", PERF_TYPE_BREAKPOINT);

	return register_die_notifier(&hw_breakpoint_exceptions_nb);

err_alloc:
	for_each_possible_cpu(err_cpu) {
		for (i = 0; i < TYPE_MAX; i++)
			kfree(get_bp_info(err_cpu, i)->tsk_pinned);
		if (err_cpu == cpu)
			break;
	}
	return -ENOMEM;
}
