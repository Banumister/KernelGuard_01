/*
 * KernelGuard :: Week 1 - eBPF execve() interceptor
 * ---------------------------------------------------
 * Hooks the execve() syscall entry point via a kprobe and streams every
 * process-execution event (pid, ppid, comm, filename) up to user space
 * through a BPF perf buffer.
 *
 * This is the "Ring 0" sensor: it runs inside the Linux kernel and cannot
 * be tampered with by the Python process it is watching.
 *
 * Loaded and attached by controller/bpf_loader.py (bcc rewrites this
 * source with kernel-specific headers at load time, so it will NOT
 * compile standalone with a plain `gcc` invocation).
 *
 * Roadmap:
 *   Week 1 (this file): log-only execve() tracing.
 *   Week 2: add tcp_connect / vfs_write hooks (see ebpf/week2_*.c, TODO).
 *   Week 3: upgrade from IDS (log) to IPS (block) by returning -EPERM.
 */

#include <linux/sched.h>

#define ARGSIZE 128

struct data_t {
    u32  pid;                    /* PID of the process calling execve()   */
    u32  ppid;                   /* Parent PID                            */
    char comm[TASK_COMM_LEN];    /* Process name (e.g. "python3")         */
    char filename[ARGSIZE];      /* Path of the binary being executed     */
};

BPF_PERF_OUTPUT(events);

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                  const char __user *const __user *argv,
                  const char __user *const __user *envp)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
