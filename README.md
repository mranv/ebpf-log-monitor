# eBPF Log Monitor

A security-focused eBPF-based system log monitoring tool built with Rust that captures and analyzes security-relevant events on Linux systems. This tool leverages the power of eBPF to observe system events with minimal overhead and provides real-time security insights.

## Features

- **System Call Monitoring**: Track and log security-sensitive system calls
- **Process Execution Tracking**: Monitor program executions across the system
- **File Access Monitoring**: Log file access patterns for sensitive files
- **Network Connection Tracking**: Monitor outbound connections
- **Privilege Escalation Detection**: Identify potential privilege escalation attempts
- **Threat Analytics**: Track and report suspicious processes and activities
- **Flexible Output Formats**: Support for both human-readable and JSON outputs
- **Log File Integration**: Optional logging to file for persistent records

## Requirements

This tool requires:

- Arch Linux or other Arch-based distribution (can be adapted for other Linux distributions)
- Linux kernel 5.8+ (recommended for full eBPF functionality)
- Root/sudo privileges (required for eBPF operations)

## Installation

### 1. Install Dependencies

For Arch Linux:

```bash
# Install base development tools
sudo pacman -S base-devel

# Install Rust and Cargo
sudo pacman -S rustup
rustup default stable

# Install LLVM, Clang, and BPF development tools
sudo pacman -S llvm clang libelf linux-headers bpfcc-tools libbpf
```

### 2. Clone Repository and Build

```bash
# Clone the repository
git clone https://github.com/yourusername/ebpf-log-monitor.git
cd ebpf-log-monitor

# Build the project
cargo build --release
```

## Usage

The monitoring tool requires root privileges to load and attach eBPF programs:

```bash
sudo ./target/release/ebpf-log-monitor [OPTIONS]
```

### Command-line Options

```
OPTIONS:
    -i, --interval <SECONDS>    Set the statistics reporting interval [default: 5]
    -l, --log-file <FILE>       Specify a log file for persistent logging
    -f, --format <FORMAT>       Output format: text or json [default: text]
    -s, --severity <LEVEL>      Minimum severity to report: info, warn, critical [default: info]
    -h, --help                  Print help information
```

### Example Commands

Monitor with default settings:
```bash
sudo ./target/release/ebpf-log-monitor
```

Monitor and save logs to file:
```bash
sudo ./target/release/ebpf-log-monitor --log-file /var/log/security-monitor.log
```

Focus on critical security events with JSON output:
```bash
sudo ./target/release/ebpf-log-monitor --severity critical --format json
```

## Security Considerations

- This tool requires privileged access to the system to operate
- Consider the implications of logging sensitive system activity
- Review and customize the eBPF programs to match your security requirements
- Implement proper log management and rotation if using the file logging option

## Troubleshooting

### Common Issues

1. **Verifier errors**: If you see "failed to verify BPF program" errors, your kernel might have different structure layouts than expected. Consider updating to a newer kernel or adjusting the BPF program.

2. **Missing BTF info**: If you see errors related to BTF (BPF Type Format), ensure your kernel was built with CONFIG_DEBUG_INFO_BTF=y or consider using a distribution-provided kernel with BTF support.

3. **Permission denied**: Make sure you're running the tool with sudo or as root.

### Debug Logging

To enable more verbose logging:

```bash
RUST_LOG=debug sudo -E ./target/release/ebpf-log-monitor
```

## Performance Impact

The eBPF-based monitoring is designed to have minimal impact on system performance. However, monitoring a large number of events on a busy system can still introduce some overhead. Consider:

- Using more targeted event monitoring for production systems
- Adjusting the statistics reporting interval for lower CPU usage
- Running benchmarks before deploying in performance-sensitive environments

## Customization

### Adding New Event Types

1. Define the new event type in `src/bpf/log_monitor.h`
2. Add the corresponding tracepoint/kprobe in `src/bpf/log_monitor.bpf.c`
3. Update the event handling in `src/main.rs`

### Custom Security Policies

Modify the severity assignments in the BPF program based on your security policies and threat model.

## License

This project is licensed under the GPL-2.0 License - see the LICENSE file for details.

## Acknowledgments

- Based on the eBPF and Rust integration approaches described in community articles and documentation
- Inspired by modern observability and security monitoring frameworks
