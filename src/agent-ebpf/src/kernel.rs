use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{trace_point::TracePointLinkId, TracePoint},
    util::online_cpus,
    Bpf, Ebpf,
};
use bytes::BytesMut;
use openxdr_common::ExecveEvent;
use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    path::Path,
};
use tokio::io::AsyncReadExt;
/**
 * EbpfKernel struct
 *
 * @member bpf: Bpf instance
 * @member links: HashMap of trace point links
 */
pub struct EbpfKernel {
    bpf: Ebpf,
    links: HashMap<String, aya::programs::trace_point::TracePointLinkId>,
}

/**
 * EbpfKernel implementation
 *
 * @member new: Create a new EbpfKernel instance
 * @member attach_execve: Attach the execve tracepoint
 * @member open_execve_events: Open the execve events map
 */
impl EbpfKernel {
    /**
     * Create a new EbpfKernel instance
     *
     * @param data: eBPF program data
     * @return: EbpfKernel instance
     */
    pub fn new(data: &[u8]) -> anyhow::Result<Self> {
        let bpf = Ebpf::load(data)?;
        Ok(Self {
            bpf,
            links: HashMap::new(),
        })
    }

    /**
     * Attach the execve tracepoint
     *
     * @return: Result  
     */
    pub fn attach_execve(&mut self) -> anyhow::Result<()> {
        // Attach execve
        let program: &mut TracePoint = self
            .bpf
            .program_mut("execve_enter")
            .ok_or_else(|| anyhow::anyhow!("Program 'execve_enter' not found"))?
            .try_into()?;
        program.load()?;
        let link_id = program.attach("syscalls/sys_enter_execve", "")?;
        self.links.insert("execve_enter".into(), link_id);

        // Attach execveat
        let program_at: &mut TracePoint = self
            .bpf
            .program_mut("execveat_enter")
            .ok_or_else(|| anyhow::anyhow!("Program 'execveat_enter' not found"))?
            .try_into()?;
        program_at.load()?;
        let link_id_at = program_at.attach("syscalls/sys_enter_execveat", "")?;
        self.links.insert("execveat_enter".into(), link_id_at);

        Ok(())
    }

    pub fn attach_file_monitoring(&mut self) -> anyhow::Result<()> {
        let program_openat: &mut TracePoint = self
            .bpf
            .program_mut("openat_enter")
            .ok_or_else(|| anyhow::anyhow!("Program 'openat_enter' not found"))?
            .try_into()?;
        program_openat.load()?;
        // attach to sys_enter_openat
        let _ = program_openat.attach("syscalls/sys_enter_openat", "")?;

        Ok(())
    }

    pub fn take_file_events(&mut self) -> anyhow::Result<AsyncPerfEventArray<aya::maps::MapData>> {
        let map = self
            .bpf
            .take_map("EVENTS_FILE")
            .ok_or_else(|| anyhow::anyhow!("Map 'EVENTS_FILE' not found"))?;

        AsyncPerfEventArray::try_from(map).map_err(Into::into)
    }

    pub fn take_execve_events(
        &mut self,
    ) -> anyhow::Result<AsyncPerfEventArray<aya::maps::MapData>> {
        let map = self
            .bpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("Map 'EVENTS' not found"))?;

        AsyncPerfEventArray::try_from(map).map_err(Into::into)
    }
}
