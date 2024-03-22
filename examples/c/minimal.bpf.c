// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
//#include <linux/bpf.h>
#include "../../vmlinux/x86/vmlinux.h"
#include "../../vmlinux/loongarch/vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "/usr/include/bpf/bpf_core_read.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	struct task_struct *prev;
        if(bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_current_task_btf)
                && (bpf_core_enum_value(enum bpf_func_id, BPF_FUNC_get_current_task_btf) == BPF_FUNC_get_current_task_btf))
        {
                prev = (struct task_struct *)bpf_get_current_task_btf();
        }
        else
        {
                prev = (struct task_struct *)bpf_get_current_task();
        }
	int result_mm_rss = bpf_core_type_exists(struct mm_rss_stat);
	int result_rss = bpf_core_type_exists(struct rss_stat);
	//需要测试存在该结构体字段的情况和不存在的情况
	int result_task_state = bpf_core_field_exists(prev->__state);
	int result_task_oncpu = bpf_core_field_exists(prev->on_cpu);
	//需要测试存在该函数字段的情况和不存在的情况
/*	string test_struct = "((struct kernel_cap_t *)0)->val"
	int result_bpf_func_task_btf = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_current_task_btf);
	int result_cap_struct = bpf_core_field_exists(((struct kernel_cap_struct *)0)->cap);
	int result_cap_t = bpf_core_field_exists(test_struct); */
	if (pid != my_pid)
		return 0;

	if (bpf_core_type_exists(struct mm_rss_stat)){
		bpf_printk("find mm_rss_stat\n");
	}

//	bpf_printk("BPF triggered from PID %d.\n                and result_mm_rss = %d \n                       and result_rss = %d \n          and result_task_state = %d \n                                   and result_bpf_func_id_BPF_FUNC_get_current_task_btf = %d \n",                  pid, result_mm_rss, result_rss, result_task_state, result_bpf_func_task_btf);
//	bpf_printk("result_cap_struct = %d \n", result_cap_struct);
//	bpf_printk("result_cap_t = %d \n", result_cap_t);
	bpf_printk("result_task_state  = %d \n", result_task_state);
	bpf_printk("result_task_oncpu = %d \n", result_task_oncpu);
	struct inode *exe_inode = BPF_CORE_READ(prev, mm, exe_file, f_inode);
	int result_exe_ictime = bpf_core_field_exists(exe_inode->i_ctime);
        int result_exe_imtime = bpf_core_field_exists(exe_inode->i_mtime);
	bpf_printk("result_exe_ictime = %d\n", result_exe_ictime);
        bpf_printk("result_exe_imtime = %d\n", result_exe_imtime);
	return 0;
}
