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