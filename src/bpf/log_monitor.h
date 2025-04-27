#ifndef LOG_MONITOR_H
#define LOG_MONITOR_H

/* Event types for various log events */
#define EVENT_SYSCALL     0
#define EVENT_FILEACCESS  1
#define EVENT_NETACCESS   2
#define EVENT_EXEC        3
#define EVENT_SECURITY    4

/* Maximum log message length */
#define MAX_MSG_SIZE      256

/* Security event severity levels */
#define SEVERITY_INFO     0
#define SEVERITY_WARN     1
#define SEVERITY_CRITICAL 2

struct log_event {
    /* Timestamp in nanoseconds */
    __u64 ts;

    /* Process info */
    __u32 pid;
    __u32 uid;
    __u32 gid;

    /* Event classification */
    __u8 event_type;
    __u8 severity;

    /* Event details */
    __u32 syscall_id;      /* For syscall events */
    __u64 address;         /* Memory or file address if relevant */

    /* Process name */
    char comm[16];

    /* Log message */
    char message[MAX_MSG_SIZE];
};

#endif /* LOG_MONITOR_H */
