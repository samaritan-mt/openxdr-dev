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

    /**
     * Open the execve events map
     *
     * @return: AsyncPerfEventArray : Array of events
     */
    pub fn open_execve_events(
        &mut self,
    ) -> anyhow::Result<AsyncPerfEventArray<&mut aya::maps::MapData>> {
        let map = self
            .bpf
            .map_mut("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("Map 'EVENTS' not found"))?;

        AsyncPerfEventArray::try_from(map).map_err(Into::into)
    }
}
