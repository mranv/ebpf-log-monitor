use anyhow::{bail, Result};
use clap::Parser;
use libbpf_rs::{PerfBufferBuilder, skel::{OpenSkel, Skel, SkelBuilder}};
use std::{
    fs::OpenOptions,
    io::Write,
    process,
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    time::Duration,
};
use time::{format_description, OffsetDateTime};
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;
use std::collections::HashMap;
use serde::Serialize;

// Include the auto-generated BPF skeleton code
mod log_monitor {
    include!(concat!(env!("OUT_DIR"), "/log_monitor.skel.rs"));
}

use log_monitor::*;

// Event types
const EVENT_SYSCALL: u8 = 0;
const EVENT_FILEACCESS: u8 = 1;
const EVENT_NETACCESS: u8 = 2;
const EVENT_EXEC: u8 = 3;
const EVENT_SECURITY: u8 = 4;

// Severity levels
const SEVERITY_INFO: u8 = 0;
const SEVERITY_WARN: u8 = 1;
const SEVERITY_CRITICAL: u8 = 2;

// Maximum message size
const MAX_MSG_SIZE: usize = 256;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct LogEvent {
    ts: u64,
    pid: u32,
    uid: u32,
    gid: u32,
    event_type: u8,
    severity: u8,
    syscall_id: u32,
    address: u64,
    comm: [u8; 16],
    message: [u8; MAX_MSG_SIZE],
}

#[derive(Debug, Serialize)]
struct FormattedLogEvent {
    timestamp: String,
    pid: u32,
    uid: u32,
    gid: u32,
    process_name: String,
    event_type: String,
    severity: String,
    message: String,
    syscall_id: Option<u32>,
    address: Option<u64>,
}

#[derive(Debug, Parser)]
#[clap(name = "ebpf-log-monitor", about = "A security-focused eBPF log monitoring tool")]
struct Command {
    /// Monitoring interval in seconds
    #[clap(short, long, default_value = "5")]
    interval: u64,

    /// Log file path (if not provided, logs will only go to stdout)
    #[clap(short, long)]
    log_file: Option<String>,

    /// Output format (text or json)
    #[clap(short, long, default_value = "text")]
    format: String,

    /// Filter logs by minimal severity (info, warn, critical)
    #[clap(short, long, default_value = "info")]
    severity: String,
}

fn main() -> Result<()> {
    // Parse command line arguments
    let opts = Command::parse();

    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Set up signal handler for graceful termination
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        info!("Received Ctrl+C, shutting down...");
        r.store(false, Ordering::SeqCst);
    })?;

    // Build and load the eBPF program
    let builder = LogMonitorSkelBuilder::default();
    let open_skel = builder.open()?;
    let mut skel = open_skel.load()?;

    // Attach the eBPF program
    if let Err(e) = skel.attach() {
        bail!("Failed to attach BPF program: {}", e);
    }

    info!("Successfully loaded and attached eBPF log monitoring program");

    // Determine minimum severity level for filtering
    let min_severity = match opts.severity.as_str() {
        "info" => SEVERITY_INFO,
        "warn" => SEVERITY_WARN,
        "critical" => SEVERITY_CRITICAL,
        _ => {
            warn!("Unknown severity level '{}', defaulting to 'info'", opts.severity);
            SEVERITY_INFO
        }
    };

    // Keep track of detected threats/suspicious activities
    let mut threat_counts: HashMap<String, u32> = HashMap::new();

    // Set up perf buffer for events
    let perf = PerfBufferBuilder::new(skel.maps_mut().log_events())
        .sample_cb(|cpu, data| {
            handle_event(cpu, data, &opts, min_severity, &mut threat_counts);
        })
        .lost_cb(handle_lost_events)
        .build()?;

    info!("Log monitoring started. Press Ctrl+C to stop...");

    // Main loop - poll for events and periodically show stats
    let mut last_stats_time = std::time::Instant::now();
    while running.load(Ordering::SeqCst) {
        // Poll for new events
        if let Err(e) = perf.poll(Duration::from_millis(100)) {
            if e.raw_os_error() == Some(libc::EINTR) {
                break;
            }
            warn!("Error polling perf buffer: {}", e);
        }

        // Periodically print statistics
        let now = std::time::Instant::now();
        if now.duration_since(last_stats_time).as_secs() >= opts.interval {
            print_statistics(&threat_counts);
            last_stats_time = now;
        }
    }

    // Final statistics on exit
    info!("Final threat statistics:");
    print_statistics(&threat_counts);

    info!("Monitoring stopped, exiting...");
    Ok(())
}

fn handle_event(
    _cpu: i32,
    data: &[u8],
    opts: &Command,
    min_severity: u8,
    threat_counts: &mut HashMap<String, u32>
) {
    // Parse the event data
    let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const LogEvent) };

    // Skip events below the minimum severity level
    if event.event_type == EVENT_SECURITY && event.severity < min_severity {
        return;
    }

    // Format the event for display/logging
    let formatted_event = format_event(&event);

    // Count threats by process name for statistics
    if event.event_type == EVENT_SECURITY && event.severity >= SEVERITY_WARN {
        let process = formatted_event.process_name.clone();
        *threat_counts.entry(process).or_insert(0) += 1;
    }

    // Output the event based on the specified format
    match opts.format.as_str() {
        "json" => {
            if let Ok(json) = serde_json::to_string(&formatted_event) {
                println!("{}", json);

                // Also write to log file if specified
                if let Some(log_file) = &opts.log_file {
                    write_to_log_file(log_file, &json);
                }
            }
        },
        _ => {
            // Default text format
            let severity_marker = match formatted_event.severity.as_str() {
                "CRITICAL" => "!!!",
                "WARNING" => " ! ",
                _ => "   ",
            };

            let log_line = format!(
                "[{}] {} [{}] {} (PID:{}) - {}",
                formatted_event.timestamp,
                severity_marker,
                formatted_event.event_type,
                formatted_event.process_name,
                formatted_event.pid,
                formatted_event.message
            );

            println!("{}", log_line);

            // Also write to log file if specified
            if let Some(log_file) = &opts.log_file {
                write_to_log_file(log_file, &log_line);
            }
        }
    }
}

fn format_event(event: &LogEvent) -> FormattedLogEvent {
    // Convert timestamp to human-readable format
    let ts_ns = event.ts;
    let ts_sec = (ts_ns / 1_000_000_000) as i64;
    let ts_nsec = (ts_ns % 1_000_000_000) as u32;

    let date_time = match OffsetDateTime::from_unix_timestamp(ts_sec) {
        Ok(dt) => dt.replace_nanosecond(ts_nsec).unwrap(),
        Err(_) => OffsetDateTime::now_utc(),
    };

    let format = format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]").unwrap();
    let time_str = date_time.format(&format).unwrap_or_default();

    // Convert process name from raw bytes
    let comm = std::str::from_utf8(&event.comm)
        .unwrap_or("unknown")
        .trim_matches(char::from(0))
        .to_string();

    // Convert message from raw bytes
    let msg = std::str::from_utf8(&event.message)
        .unwrap_or("unknown")
        .trim_matches(char::from(0))
        .to_string();

    // Map event type to string
    let event_type = match event.event_type {
        EVENT_SYSCALL => "SYSCALL",
        EVENT_FILEACCESS => "FILE_ACCESS",
        EVENT_NETACCESS => "NETWORK",
        EVENT_EXEC => "EXECUTION",
        EVENT_SECURITY => "SECURITY",
        _ => "UNKNOWN",
    };

    // Map severity to string
    let severity = match event.severity {
        SEVERITY_INFO => "INFO",
        SEVERITY_WARN => "WARNING",
        SEVERITY_CRITICAL => "CRITICAL",
        _ => "UNKNOWN",
    };

    // Create formatted event
    FormattedLogEvent {
        timestamp: time_str,
        pid: event.pid,
        uid: event.uid,
        gid: event.gid,
        process_name: comm,
        event_type: event_type.to_string(),
        severity: severity.to_string(),
        message: msg,
        syscall_id: if event.syscall_id > 0 { Some(event.syscall_id) } else { None },
        address: if event.address > 0 { Some(event.address) } else { None },
    }
}

fn write_to_log_file(file_path: &str, content: &str) {
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
    {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{}", content) {
                error!("Failed to write to log file: {}", e);
            }
        },
        Err(e) => {
            error!("Failed to open log file {}: {}", file_path, e);
        }
    }
}

fn handle_lost_events(cpu: i32, count: u64) {
    warn!("Lost {} events on CPU {}", count, cpu);
}

fn print_statistics(threat_counts: &HashMap<String, u32>) {
    if threat_counts.is_empty() {
        info!("No security threats detected yet.");
        return;
    }

    // Sort threats by count (descending)
    let mut threats: Vec<(&String, &u32)> = threat_counts.iter().collect();
    threats.sort_by(|a, b| b.1.cmp(a.1));

    info!("Top security threats by process:");
    for (i, (process, count)) in threats.iter().enumerate().take(10) {
        info!("{:2}. {:20} - {} suspicious events", i + 1, process, count);
    }
}
