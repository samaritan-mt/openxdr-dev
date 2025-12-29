mod agent;
use agent::config::global_to_string;
use agent::user::UserManager;
#[cfg(target_os = "linux")]
use agent_ebpf::kernel::EbpfKernel;
use bytes::BytesMut;
use openxdr_common::ExecveEvent;
use std::fs;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let agent_config = agent::config::Config::load_default().expect("Failed to load agent config");
    println!("Agent Configuration:");
    println!("{}", global_to_string(&agent_config));

    start_agent().await?;

    Ok(())
}

#[cfg(target_os = "linux")]
async fn start_agent() -> anyhow::Result<()> {
    // Determine path to eBPF program
    let ebpf_path = "target/bpfel-unknown-none/release/openxdr-ebpf";
    println!("Loading eBPF program from {}", ebpf_path);
    match fs::read(ebpf_path) {
        Ok(data) => {
            let mut kernel = EbpfKernel::new(&data)?;
            kernel.attach_execve()?;
            let mut events = kernel.open_execve_events()?;
            println!("eBPF attached. Listening for events...");
            let cpus = aya::util::online_cpus().map_err(|(_, error)| {
                anyhow::anyhow!("Failed to get online cpus: {}", error)
            })?;
            let user_manager = UserManager::new();

            let mut loops = Vec::new();

            for cpu in cpus {
                let mut buf = events.open(cpu, None)?;
                let user_manager = user_manager.clone();

                loops.push(async move {
                    let mut buffers = vec![BytesMut::with_capacity(1024); 10];
                    loop {
                        match buf.read_events(&mut buffers).await {
                            Ok(events_read) => {
                                println!("Read {} events", events_read.read);
                                for i in 0..events_read.read {
                                    let buf = &mut buffers[i];
                                    if buf.len() >= std::mem::size_of::<ExecveEvent>() {
                                        let evt_ptr = buf.as_ptr() as *const ExecveEvent;
                                        let evt = unsafe { std::ptr::read_unaligned(evt_ptr) };

                                        let comm = String::from_utf8_lossy(&evt.comm)
                                            .trim_matches('\0')
                                            .to_string();
                                        let filename = String::from_utf8_lossy(&evt.filename)
                                            .trim_matches('\0')
                                            .to_string();
                                        let username = user_manager.get_user(evt.uid);
                                        if evt.uid != 0 {
                                            println!(
                                                "EXECVE: pid={} user={} comm={} filename={}",
                                                evt.pid, username, comm, filename
                                            );
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Error reading events on cpu {}: {}", cpu, e);
                                break;
                            }
                        }
                    }
                });
            }

            tokio::select! {
                _ = futures::future::join_all(loops) => {},
                _ = signal::ctrl_c() => {
                    println!("Exiting...");
                }
            }
        }
        Err(e) => {
            eprintln!(
                "Failed to read eBPF program: {}. Make sure to build openxdr-ebpf first.",
                e
            );
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn start_agent() -> anyhow::Result<()> {
    println!("Not running on Linux, eBPF features are disabled.");
    println!("Staring dummy agent loop...");
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}
