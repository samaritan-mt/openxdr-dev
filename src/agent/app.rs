use crate::agent::{self, config::Config, user::UserManager};
use anyhow::Result;
use bytes::BytesMut;
use futures::future::join_all;
use std::borrow::Cow;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
use agent_ebpf::kernel::EbpfKernel;

fn parse_cstr(bytes: &[u8]) -> String {
    if let Some(nul_pos) = bytes.iter().position(|&c| c == 0) {
        String::from_utf8_lossy(&bytes[..nul_pos]).to_string()
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

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

        let abi = agent::syscall_abi::SyscallAbi::discover();   
        abi.report();               

        let mut kernel = EbpfKernel::new(&data, &abi.return_offset_struct())?;
        kernel.attach_execve()?;
        kernel.attach_file_monitoring(abi.has_open, abi.discovered)?; // Attach FIM probes
        kernel.attach_module_monitoring()?; // Attach kernel module probes
        kernel.attach_network()?; // Attach network probes
        kernel.attach_lsm()?; // Attach LSM probes

        let mut events = kernel.take_execve_events()?;
        let mut file_events = kernel.take_file_events()?;
        let mut lsm_events = kernel.take_lsm_events()?;
        let mut module_events = kernel.take_module_events()?;
        let mut net_events = kernel.take_network_events()?;

        println!("eBPF attached. Listening for events...");
        let cpus = aya::util::online_cpus()
            .map_err(|(_, error)| anyhow::anyhow!("Failed to get online cpus: {}", error))?;
        let user_manager = UserManager::new();

        // Load rules and create engine
        println!("Loading rules from src/lib/sigma-rules");
        let engine = Arc::new(agent::engine::Engine::new("src/lib/sigma-rules"));

        let kernel_rules = engine.compile_kernel_rules();
        if let Err(e) = kernel.add_kernel_rules(&kernel_rules, engine.permissive_mask()) {
            // Without the fast-path the agent still detects everything, it just
            // pays full userspace cost per event. Never fatal.
            eprintln!("Failed to inject kernel rules, running unfiltered: {}", e);
        }
        engine.report_kernel_filter();

        let (tx, mut rx) = mpsc::unbounded_channel::<agent::engine::Event<'static>>();
        let engine_telemetry = engine.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                engine_telemetry.process_event(&ev);
            }
        });

        let mut loops: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> =
            Vec::new();

        for cpu in cpus {
            // Execve Loop
            let mut buf = events.open(cpu, None)?;
            let user_manager_exec = user_manager.clone();
            let tx_exec = tx.clone();

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

                                    let comm_str = parse_cstr(&evt.comm);
                                    let filename_str = parse_cstr(&evt.filename);
                                    let username = user_manager_exec.get_user(evt.uid);

                                    let mut args = Vec::new();
                                    let argc = evt.argc as usize;
                                    for i in 0..8 {
                                        if i >= argc {
                                            break;
                                        }
                                        let offset = i * 128;
                                        if offset + 128 <= evt.argv.len() {
                                            let arg_str = parse_cstr(&evt.argv[offset..offset + 128]);
                                            if !arg_str.is_empty() {
                                                args.push(arg_str);
                                            }
                                        }
                                    }
                                    let clean_args_str = args.join(" ");
                                    let cmdline = if !clean_args_str.is_empty() {
                                        Cow::Owned(clean_args_str)
                                    } else {
                                        Cow::Borrowed(filename_str.as_str())
                                    };

                                    if evt.uid != 0 {
                                        println!(
                                            "DEBUG: Received EXECVE: comm={} file={} uid={} user={:?} pid={} cmdline={:?} syscall={:?} file_path={:?}",
                                            comm_str, filename_str, evt.uid, username.trim_matches('\0'), evt.pid, cmdline.trim_matches('\0'), "execve", filename_str
                                        );
                                    }

                                    // Create engine event
                                    let engine_event = agent::engine::Event {
                                        event_type: Cow::Borrowed("EXECVE"),
                                        process_name: Cow::Owned(comm_str.to_string()),
                                        uid: evt.uid,
                                        user_name: Cow::Owned(username),
                                        pid: evt.pid,
                                        cmdline: Some(Cow::Owned(cmdline.into_owned())),
                                        syscall: Some(Cow::Borrowed("execve")),
                                        file_path: Some(Cow::Owned(filename_str.to_string())),
                                        is_write: None,
                                        network: None,
                                    };
                                    let _ = tx_exec.send(engine_event);
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
            let tx_file = tx.clone();

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

                                    let comm_str = parse_cstr(&evt.comm);
                                    let path_str = parse_cstr(&evt.path);
                                    let username = user_manager_file.get_user(evt.uid);

                                    let is_write = (evt.flags & 0o1) != 0
                                        || (evt.flags & 0o2) != 0
                                        || (evt.flags & 0o100) != 0
                                        || (evt.flags & 0o1000) != 0
                                        || (evt.flags & 0o2000) != 0;

                                    // Create engine event
                                    let engine_event = agent::engine::Event {
                                        event_type: Cow::Borrowed("SYSCALL"),
                                        process_name: Cow::Owned(comm_str.to_string()),
                                        uid: evt.uid,
                                        user_name: Cow::Owned(username),
                                        pid: evt.pid,
                                        cmdline: Some(Cow::Owned(comm_str.to_string())),
                                        syscall: Some(Cow::Borrowed("openat")),
                                        file_path: Some(Cow::Owned(path_str.to_string())),
                                        is_write: Some(is_write),
                                        network: None,
                                    };

                                    let _ = tx_file.send(engine_event);
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

            // --- LSM Loop ---
            let mut lsm_buf = lsm_events.open(cpu, None)?;
            let tx_lsm = tx.clone();
            let user_manager_lsm = user_manager.clone();

            loops.push(Box::pin(async move {
                let mut buffers = vec![BytesMut::with_capacity(256); 10];
                loop {
                    match lsm_buf.read_events(&mut buffers).await {
                        Ok(events_read) => {
                            for i in 0..events_read.read {
                                let buf = &mut buffers[i];
                                if buf.len() >= std::mem::size_of::<openxdr_common::LSMEvent>() {
                                    let evt_ptr = buf.as_ptr() as *const openxdr_common::LSMEvent;
                                    let evt = unsafe { std::ptr::read_unaligned(evt_ptr) };

                                    let comm_str = parse_cstr(&evt.comm);
                                    let username = user_manager_lsm.get_user(evt.uid);
                                    let file_path = if evt.filename[0] != 0 {
                                        Some(Cow::Owned(parse_cstr(&evt.filename)))
                                    } else {
                                        None
                                    };

                                    let engine_event = agent::engine::Event {
                                        event_type: Cow::Borrowed("LSM"),
                                        process_name: Cow::Owned(comm_str.to_string()),
                                        uid: evt.uid,
                                        user_name: Cow::Owned(username),
                                        pid: evt.pid,
                                        cmdline: None,
                                        syscall: None,
                                        file_path,
                                        is_write: None,
                                        network: None,
                                    };
                                    let _ = tx_lsm.send(engine_event);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading LSM events on cpu {}: {}", cpu, e);
                            break;
                        }
                    }
                }
            }));

            // --- Module Loop ---
            let mut module_buf = module_events.open(cpu, None)?;
            let tx_mod = tx.clone();
            let user_manager_mod = user_manager.clone();

            loops.push(Box::pin(async move {
                let mut buffers = vec![BytesMut::with_capacity(256); 10];
                loop {
                    match module_buf.read_events(&mut buffers).await {
                        Ok(events_read) => {
                            for i in 0..events_read.read {
                                let buf = &mut buffers[i];
                                if buf.len() >= std::mem::size_of::<openxdr_common::ModuleEvent>() {
                                    let evt_ptr =
                                        buf.as_ptr() as *const openxdr_common::ModuleEvent;
                                    let evt = unsafe { std::ptr::read_unaligned(evt_ptr) };

                                    let comm_str = parse_cstr(&evt.comm);
                                    let username = user_manager_mod.get_user(evt.uid);
                                    let syscall = if evt.kind == 0 {
                                        "init_module"
                                    } else {
                                        "finit_module"
                                    };

                                    println!(
                                        "DEBUG: Received MODULE: comm={} uid={} pid={} syscall={}",
                                        comm_str, evt.uid, evt.pid, syscall
                                    );

                                    let engine_event = agent::engine::Event {
                                        event_type: Cow::Borrowed("SYSCALL"),
                                        process_name: Cow::Owned(comm_str.to_string()),
                                        uid: evt.uid,
                                        user_name: Cow::Owned(username),
                                        pid: evt.pid,
                                        cmdline: None,
                                        syscall: Some(Cow::Borrowed(syscall)),
                                        file_path: None,
                                        is_write: None,
                                        network: None,
                                    };
                                    let _ = tx_mod.send(engine_event);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading module events on cpu {}: {}", cpu, e);
                            break;
                        }
                    }
                }
            }));

            // --- Network Loop ---
            let mut net_buf = net_events.open(cpu, None)?;
            let tx_net = tx.clone();
            let user_manager_net = user_manager.clone();

            loops.push(Box::pin(async move {
                let mut buffers = vec![BytesMut::with_capacity(256); 10];
                loop {
                    match net_buf.read_events(&mut buffers).await {
                        Ok(events_read) => {
                            for i in 0..events_read.read {
                                let buf = &mut buffers[i];
                                if buf.len() >= std::mem::size_of::<openxdr_common::NetworkEvent>()
                                {
                                    let evt_ptr =
                                        buf.as_ptr() as *const openxdr_common::NetworkEvent;
                                    let evt = unsafe { std::ptr::read_unaligned(evt_ptr) };

                                    let comm_str = parse_cstr(&evt.comm);
                                    let username = user_manager_net.get_user(evt.uid);

                                    let ip = if evt.is_ipv6 == 0 {
                                        let mut ipv4_bytes = [0u8; 4];
                                        ipv4_bytes.copy_from_slice(&evt.daddr[..4]);
                                        std::net::Ipv4Addr::from(u32::from_be_bytes(ipv4_bytes))
                                            .to_string()
                                    } else {
                                        let mut ipv6_bytes = [0u8; 16];
                                        ipv6_bytes.copy_from_slice(&evt.daddr);
                                        std::net::Ipv6Addr::from(ipv6_bytes).to_string()
                                    };
                                    let port = u16::from_be(evt.dport);

                                    let engine_event = agent::engine::Event {
                                        event_type: Cow::Borrowed("NETWORK"),
                                        process_name: Cow::Owned(comm_str.to_string()),
                                        uid: evt.uid,
                                        user_name: Cow::Owned(username),
                                        pid: evt.pid,
                                        cmdline: None,
                                        syscall: Some(Cow::Borrowed("connect")),
                                        file_path: None,
                                        network: Some(agent::engine::NetworkDetails {
                                            dest_ip: Cow::Owned(ip),
                                            dest_port: port,
                                        }),
                                        is_write: None,
                                    };
                                    let _ = tx_net.send(engine_event);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Error reading net events on cpu {}: {}", cpu, e);
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
