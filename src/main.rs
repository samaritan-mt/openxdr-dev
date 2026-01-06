mod agent;
use agent::config::global_to_string;
use agent::engine::Engine;
use agent::user::UserManager;
#[cfg(target_os = "linux")]
use agent_ebpf::kernel::EbpfKernel;
use bytes::BytesMut;
use std::fs;
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let agent_config = agent::config::Config::load_default().expect("Failed to load agent config");
    println!("Agent Configuration:");
    println!("{}", global_to_string(&agent_config));

    start_agent(&agent_config).await?;

    Ok(())
}

#[cfg(target_os = "linux")]
async fn start_agent(config: &agent::config::Config) -> anyhow::Result<()> {
    // Determine path to eBPF program
    let ebpf_path = "target/bpfel-unknown-none/release/openxdr-ebpf";
    println!("Loading eBPF program from {}", ebpf_path);
    match fs::read(ebpf_path) {
        Ok(data) => {
            let mut kernel = EbpfKernel::new(&data)?;
            kernel.attach_execve()?;
            kernel.attach_file_monitoring()?; // Attach FIM probes

            let mut events = kernel.take_execve_events()?;
            let mut file_events = kernel.take_file_events()?;

            println!("eBPF attached. Listening for events...");
            let cpus = aya::util::online_cpus()
                .map_err(|(_, error)| anyhow::anyhow!("Failed to get online cpus: {}", error))?;
            let user_manager = UserManager::new();

            // Load rules and create engine
            println!("Loading rules from {:?}", config.rules_path);
            let rules = agent::rule::load_rules(&config.rules_path)?;
            let engine = std::sync::Arc::new(agent::engine::Engine::new(rules.rules));

            let mut loops: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
                Vec::new();

            for cpu in cpus {
                // Execve Loop
                let mut buf = events.open(cpu, None)?;
                let user_manager_exec = user_manager.clone();
                let engine_exec = engine.clone();

                loops.push(Box::pin(async move {
                    let mut buffers = vec![BytesMut::with_capacity(1024); 10];
                    loop {
                        match buf.read_events(&mut buffers).await {
                            Ok(events_read) => {
                                for i in 0..events_read.read {
                                    let buf = &mut buffers[i];
                                    if buf.len()
                                        >= std::mem::size_of::<openxdr_common::ExecveEvent>()
                                    {
                                        let evt_ptr =
                                            buf.as_ptr() as *const openxdr_common::ExecveEvent;
                                        let evt = unsafe { std::ptr::read_unaligned(evt_ptr) };

                                        let comm = String::from_utf8_lossy(&evt.comm)
                                            .trim_matches('\0')
                                            .to_string();
                                        let filename = String::from_utf8_lossy(&evt.filename)
                                            .trim_matches('\0')
                                            .to_string();
                                        let username = user_manager_exec.get_user(evt.uid);

                                        // Create engine event
                                        let engine_event = agent::engine::Event {
                                            event_type: "EXECVE".to_string(),
                                            process_name: comm.clone(),
                                            uid: evt.uid,
                                            user_name: username.clone(),
                                            pid: evt.pid,
                                            cmdline: filename.clone(),
                                            syscall: Some("execve".to_string()),
                                            file_path: Some(filename.clone()),
                                        };

                                        engine_exec.process_event(&engine_event);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Error reading execve events on cpu {}: {}", cpu, e);
                                break;
                            }
                        }
                    }
                }));

                // File Loop
                let mut file_buf = file_events.open(cpu, None)?;
                let user_manager_file = user_manager.clone();
                let engine_file = engine.clone();

                loops.push(Box::pin(async move {
                    let mut buffers = vec![BytesMut::with_capacity(1024); 10];
                    loop {
                        match file_buf.read_events(&mut buffers).await {
                            Ok(events_read) => {
                                for i in 0..events_read.read {
                                    let buf = &mut buffers[i];
                                    if buf.len() >= std::mem::size_of::<openxdr_common::FileEvent>()
                                    {
                                        let evt_ptr =
                                            buf.as_ptr() as *const openxdr_common::FileEvent;
                                        let evt = unsafe { std::ptr::read_unaligned(evt_ptr) };

                                        let comm = String::from_utf8_lossy(&evt.comm)
                                            .trim_matches('\0')
                                            .to_string();
                                        let path = String::from_utf8_lossy(&evt.path)
                                            .trim_matches('\0')
                                            .to_string();
                                        let username = user_manager_file.get_user(evt.uid);

                                        // Create engine event
                                        let engine_event = agent::engine::Event {
                                            event_type: "SYSCALL".to_string(),
                                            process_name: comm.clone(),
                                            uid: evt.uid,
                                            user_name: username.clone(),
                                            pid: evt.pid,
                                            cmdline: comm.clone(),
                                            syscall: Some("open".to_string()),
                                            file_path: Some(path.clone()),
                                        };

                                        engine_file.process_event(&engine_event);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Error reading file events on cpu {}: {}", cpu, e);
                                break;
                            }
                        }
                    }
                }));
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
async fn start_agent(_config: &agent::config::Config) -> anyhow::Result<()> {
    println!("Not running on Linux, eBPF features are disabled.");
    println!("Staring dummy agent loop...");
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}
