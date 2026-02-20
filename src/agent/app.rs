use crate::agent::{self, config::Config, user::UserManager};
use anyhow::Result;
use bytes::BytesMut;
use futures::future::join_all;
use std::borrow::Cow;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use tokio::signal;

#[cfg(target_os = "linux")]
use agent_ebpf::kernel::EbpfKernel;

pub struct App {
    config: Config,
}

impl App {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    #[cfg(target_os = "linux")]
    pub async fn run(&self) -> Result<()> {
        // Determine path to eBPF program

        use crate::agent::rule;
        let agent_version = env!("CARGO_PKG_VERSION");
        let ebpf_filename = format!("target/bpfel-unknown-none/release/openxdr-ebpf");
        let ebpf_path = std::path::Path::new(&ebpf_filename);

        println!("Loading eBPF program from {}", ebpf_path.display());

        let data = fs::read(ebpf_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read eBPF program from {}: {}. Make sure to build openxdr-ebpf first and rename it to {}, or update the path lookup logic.",
                ebpf_path.display(),
                e,
                ebpf_filename
            )
        })?;

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
        println!("Loading rules from {:?}", self.config.rules_path);
        let rules = agent::rule::load_rules(&self.config.rules_path)?;
        println!("Loaded {} rules", rules.rules.len());
        //Compile rules using the new compile function
        let mut compiled_rules = Vec::new();
        // src/agent/app.rs
        for rule in &rules.rules {
            match rule.compile() {
                Ok(compiled) => compiled_rules.push(compiled),
                Err(e) => eprintln!("Skipping invalid rule {}: {}", rule.id, e),
            }
        }

        let engine = Arc::new(agent::engine::Engine::new(compiled_rules));

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
                                if buf.len() >= std::mem::size_of::<openxdr_common::ExecveEvent>() {
                                    let evt_ptr =
                                        buf.as_ptr() as *const openxdr_common::ExecveEvent;
                                    let evt = unsafe { std::ptr::read_unaligned(evt_ptr) };

                                    let comm_cow = String::from_utf8_lossy(&evt.comm);
                                    let comm_str = comm_cow.trim_matches('\0');
                                    let filename_cow = String::from_utf8_lossy(&evt.filename);
                                    let filename_str = filename_cow.trim_matches('\0');
                                    let username = user_manager_exec.get_user(evt.uid);

                                    let cmdline = if let Some(args_raw) = evt.args {
                                        let args_cow = String::from_utf8_lossy(&args_raw);
                                        let args_str = args_cow.trim_matches('\0');
                                        if !args_str.is_empty() {
                                            Cow::Owned(format!("{} {}", filename_str, args_str))
                                        } else {
                                            Cow::Borrowed(filename_str)
                                        }
                                    } else {
                                        Cow::Borrowed(filename_str)
                                    };

                                    if (evt.uid != 0) {
                                        println!(
                                            "DEBUG: Received EXECVE: comm={} file={} uid={} user={:?} pid={} cmdline={:?} syscall={:?} file_path={:?}",
                                            comm_str, filename_str, evt.uid, username.trim_matches('\0'), evt.pid, cmdline.trim_matches('\0'), "execve", filename_str
                                        );
                                    }

                                    // Create engine event
                                    let engine_event = agent::engine::Event {
                                        event_type: Cow::Borrowed("EXECVE"),
                                        process_name: Cow::Borrowed(comm_str),
                                        uid: evt.uid,
                                        user_name: Cow::Owned(username),
                                        pid: evt.pid,
                                        cmdline: Some(cmdline),
                                        syscall: Some(Cow::Borrowed("execve")),
                                        file_path: Some(Cow::Borrowed(filename_str)),
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
                                if buf.len() >= std::mem::size_of::<openxdr_common::FileEvent>() {
                                    let evt_ptr = buf.as_ptr() as *const openxdr_common::FileEvent;
                                    let evt = unsafe { std::ptr::read_unaligned(evt_ptr) };

                                    let comm_cow = String::from_utf8_lossy(&evt.comm);
                                    let comm_str = comm_cow.trim_matches('\0');
                                    let path_cow = String::from_utf8_lossy(&evt.path);
                                    let path_str = path_cow.trim_matches('\0');
                                    let username = user_manager_file.get_user(evt.uid);

                                    // Create engine event
                                    let engine_event = agent::engine::Event {
                                        event_type: Cow::Borrowed("SYSCALL"),
                                        process_name: Cow::Borrowed(comm_str),
                                        uid: evt.uid,
                                        user_name: Cow::Owned(username),
                                        pid: evt.pid,
                                        cmdline: Some(Cow::Borrowed(comm_str)),
                                        syscall: Some(Cow::Borrowed("open")),
                                        file_path: Some(Cow::Borrowed(path_str)),
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
            _ = join_all(loops) => {},
            _ = signal::ctrl_c() => {
                println!("Exiting...");
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn run(&self) -> Result<()> {
        println!("Not running on Linux, eBPF features are disabled.");
        println!("Starting dummy agent loop...");
        signal::ctrl_c().await?;
        println!("Exiting...");
        Ok(())
    }
}

fn get_kernel_release() -> Result<String> {
    let output = Command::new("uname").arg("-r").output()?;
    let release = String::from_utf8(output.stdout)?;
    Ok(release.trim().to_string())
}
