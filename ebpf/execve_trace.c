#include <linux/sched.h>

#define ARGSIZE 128

struct data_t {
    u32  pid;
    u32  ppid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
};

BPF_PERF_OUTPUT(events);

/* --- Active blocking (Week 3) --- */

BPF_HASH(blocked_pids, u32, u8);

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                  const char __user *const __user *argv,
                  const char __user *const __user *envp)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    u8 *blocked = blocked_pids.lookup(&data.pid);
    if (blocked != 0) {
        bpf_send_signal(9);   // SIGKILL - stop the blocked process immediately
        return 0;
    }

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

/* --- tcp_connect() tracking (Week 2) --- */

struct connect_data_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 dport;
};

BPF_HASH(currsock, u32, struct sock *);
BPF_PERF_OUTPUT(tcp_events);

int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *blocked = blocked_pids.lookup(&pid);
    if (blocked != 0) {
        bpf_send_signal(9);
        return 0;
    }

    currsock.update(&pid, &sk);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;
    }

    if (ret != 0) {
        currsock.delete(&pid);
        return 0;
    }

    struct sock *skp = *skpp;
    struct connect_data_t data = {};
    data.pid   = pid;
    data.saddr = skp->__sk_common.skc_rcv_saddr;
    data.daddr = skp->__sk_common.skc_daddr;
    data.dport = skp->__sk_common.skc_dport;

    tcp_events.perf_submit(ctx, &data, sizeof(data));
    currsock.delete(&pid);
    return 0;
}

/* --- vfs_write() tracking (Week 2) --- */

struct write_data_t {
    u32  pid;
    char comm[TASK_COMM_LEN];
    char filename[ARGSIZE];
    u32  count;
};

BPF_PERF_OUTPUT(write_events);

int trace_vfs_write(struct pt_regs *ctx, struct file *file, const char __user *buf, size_t count)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *blocked = blocked_pids.lookup(&pid);
    if (blocked != 0) {
        bpf_send_signal(9);
        return 0;
    }

    struct write_data_t data = {};
    struct dentry *de = file->f_path.dentry;

    data.pid = pid;
    data.count = count;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_kernel_str(&data.filename, sizeof(data.filename), de->d_iname);

    write_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}