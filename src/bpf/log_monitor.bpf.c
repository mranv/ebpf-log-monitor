#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "log_monitor.h"

/* BPF map to send events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} log_events SEC(".maps");

/*
 * BPF map to keep track of suspicious processes
 * Key: PID, Value: count of suspicious activities
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u32);
} suspicious_processes SEC(".maps");

/* Helper function to log security events with severity */
static inline void log_security_event(void *ctx, u8 severity, const char *msg, u32 syscall_id, u64 address)
{
    struct log_event event = {0};

    /* Get process info */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event.ts = bpf_ktime_get_ns();
    event.pid = pid_tgid >> 32;
    event.uid = uid_gid >> 32;
    event.gid = uid_gid & 0xFFFFFFFF;
    event.event_type = EVENT_SECURITY;
    event.severity = severity;
    event.syscall_id = syscall_id;
    event.address = address;

    /* Get process name */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /* Set message */
    __builtin_memcpy(event.message, msg, MAX_MSG_SIZE);

    /* Send event to userspace */
    bpf_perf_event_output(ctx, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    /* Track suspicious processes */
    if (severity >= SEVERITY_WARN) {
        u32 pid = event.pid;
        u32 *count = bpf_map_lookup_elem(&suspicious_processes, &pid);
        u32 new_count = 1;

        if (count) {
            new_count = *count + 1;
        }

        bpf_map_update_elem(&suspicious_processes, &pid, &new_count, BPF_ANY);
    }
}

/* Monitor execve syscall for program execution */
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_entry(struct trace_event_raw_sys_enter *ctx)
{
    struct log_event event = {0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();
    char comm[16];

    /* Get process name */
    bpf_get_current_comm(&comm, sizeof(comm));

    /* Fill event structure */
    event.ts = bpf_ktime_get_ns();
    event.pid = pid_tgid >> 32;
    event.uid = uid_gid >> 32;
    event.gid = uid_gid & 0xFFFFFFFF;
    event.event_type = EVENT_EXEC;

    /* Copy process name */
    __builtin_memcpy(event.comm, comm, sizeof(comm));

    /* Format log message */
    bpf_snprintf(event.message, MAX_MSG_SIZE, "Process execution: %s (PID: %d, UID: %d)",
                 comm, event.pid, event.uid);

    /* Send event to userspace */
    bpf_perf_event_output(ctx, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

/* Monitor file open operations */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_entry(struct trace_event_raw_sys_enter *ctx)
{
    struct log_event event = {0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    /* Fill event structure */
    event.ts = bpf_ktime_get_ns();
    event.pid = pid_tgid >> 32;
    event.uid = uid_gid >> 32;
    event.gid = uid_gid & 0xFFFFFFFF;
    event.event_type = EVENT_FILEACCESS;
    event.syscall_id = 257; /* openat syscall number */

    /* Get process name */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /* Format log message */
    bpf_snprintf(event.message, MAX_MSG_SIZE, "File access by %s (PID: %d)",
                 event.comm, event.pid);

    /* Send event to userspace */
    bpf_perf_event_output(ctx, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

/* Monitor security-sensitive operations - Example: setuid */
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid_entry(struct trace_event_raw_sys_enter *ctx)
{
    const char *msg = "Privilege escalation attempt: setuid syscall";

    /* Log security event with warning severity */
    log_security_event(ctx, SEVERITY_WARN, msg, 105, 0); /* 105 is setuid syscall number */

    return 0;
}

/* Monitor network connections */
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct log_event event = {0};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    /* Skip kernel threads */
    if (pid_tgid == 0)
        return 0;

    /* Fill event structure */
    event.ts = bpf_ktime_get_ns();
    event.pid = pid_tgid >> 32;
    event.uid = uid_gid >> 32;
    event.gid = uid_gid & 0xFFFFFFFF;
    event.event_type = EVENT_NETACCESS;

    /* Get process name */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /* Format log message */
    bpf_snprintf(event.message, MAX_MSG_SIZE, "Network connection attempt by %s (PID: %d)",
                 event.comm, event.pid);

    /* Send event to userspace */
    bpf_perf_event_output(ctx, &log_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
