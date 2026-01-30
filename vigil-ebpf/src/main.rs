#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{kprobe, map},
    maps::PerfEventArray, // <--- The High-Speed Data Pipe
    programs::ProbeContext,
};
use vigil_common::ConnectEvent; // <--- Our new Schema

// Define the pipe. "EVENTS" is the name of the channel.
#[map]
static EVENTS: PerfEventArray<ConnectEvent> = PerfEventArray::new(0);

#[kprobe]
pub fn vigil(ctx: ProbeContext) -> u32 {
    try_vigil(ctx).unwrap_or(0)
}

fn try_vigil(ctx: ProbeContext) -> Result<u32, u32> {
    // 1. Capture the Data
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Get name (using the new way that worked for you)
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };

    // 2. Pack the Event
    let event = ConnectEvent { pid, comm };

    // 3. Ship it!
    // This pushes the struct directly to Userspace.
    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
