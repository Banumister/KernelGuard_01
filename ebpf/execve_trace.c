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
    currsock.update(&pid, &sk);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock **skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;   // missed the entry probe for this PID
    }

    if (ret != 0) {
        currsock.delete(&pid);
        return 0;   // connect() failed, nothing to report
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