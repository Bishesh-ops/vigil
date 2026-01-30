use aya::{
    include_bytes_aligned, maps::AsyncPerfEventArray, programs::KProbe, util::online_cpus, Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{info, warn};
use tokio::{signal, task};
use vigil_common::ConnectEvent;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "true")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();
    env_logger::init();

    // 1. Load the eBPF binary
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(env!("OUT_DIR"), "/vigil")))?;

    // 2. Initialize Logger (Optional)
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // 3. Attach the Probe
    let program: &mut KProbe = bpf.program_mut("vigil").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_v4_connect", 0)?;

    // 4. Connect to the Pipe ("EVENTS")
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    // 5. Read events from all CPUs
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const ConnectEvent;
                    let event = unsafe { ptr.read_unaligned() };

                    // Convert name to string
                    let name = match std::str::from_utf8(&event.comm) {
                        Ok(s) => s.trim_matches('\0'),
                        Err(_) => "unknown",
                    };

                    println!("🚀 EVENT: App={} PID={}", name, event.pid);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
