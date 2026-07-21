use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::{Lsm, TracePoint},
    Btf, Ebpf,
};
use std::{
    collections::HashMap,
    convert::TryFrom,
};

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct KernelRuleWrapper(openxdr_common::KernelRule);

unsafe impl aya::Pod for KernelRuleWrapper {}

/**
 * EbpfKernel struct
 *
 * @member bpf: Bpf instance
 * @member links: HashMap of trace point links
 */
pub struct EbpfKernel {
    bpf: Ebpf,
    links: HashMap<String, aya::programs::trace_point::TracePointLinkId>,
    lsm_links: HashMap<String, aya::programs::lsm::LsmLinkId>,
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
            lsm_links: HashMap::new(),
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
            .program_mut("open_enter")
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

    pub fn take_lsm_events(&mut self) -> anyhow::Result<AsyncPerfEventArray<aya::maps::MapData>> {
        let map = self
            .bpf
            .take_map("EVENTS_LSM")
            .ok_or_else(|| anyhow::anyhow!("Map 'EVENTS_LSM' not found"))?;

        AsyncPerfEventArray::try_from(map).map_err(Into::into)
    }

    pub fn take_module_events(&mut self) -> anyhow::Result<AsyncPerfEventArray<aya::maps::MapData>> {
        let map = self
            .bpf
            .take_map("EVENTS_MODULE")
            .ok_or_else(|| anyhow::anyhow!("Map 'EVENTS_MODULE' not found"))?;

        AsyncPerfEventArray::try_from(map).map_err(Into::into)
    }

    pub fn attach_module_monitoring(&mut self) -> anyhow::Result<()> {
        let prog_init: &mut TracePoint = self
            .bpf
            .program_mut("init_module_enter")
            .ok_or_else(|| anyhow::anyhow!("Program 'init_module_enter' not found"))?
            .try_into()?;
        prog_init.load()?;
        prog_init.attach("syscalls/sys_enter_init_module", "")?;

        let prog_finit: &mut TracePoint = self
            .bpf
            .program_mut("finit_module_enter")
            .ok_or_else(|| anyhow::anyhow!("Program 'finit_module_enter' not found"))?
            .try_into()?;
        prog_finit.load()?;
        prog_finit.attach("syscalls/sys_enter_finit_module", "")?;

        Ok(())
    }

    pub fn take_network_events(&mut self) -> anyhow::Result<AsyncPerfEventArray<aya::maps::MapData>> {
        let map = self
            .bpf
            .take_map("EVENTS_NET")
            .ok_or_else(|| anyhow::anyhow!("Map 'EVENTS_NET' not found"))?;

        AsyncPerfEventArray::try_from(map).map_err(Into::into)
    }

    pub fn attach_network(&mut self) -> anyhow::Result<()> {
        let program: &mut TracePoint = self
            .bpf
            .program_mut("connect_enter")
            .ok_or_else(|| anyhow::anyhow!("Program 'connect_enter' not found"))?
            .try_into()?;
        program.load()?;
        program.attach("syscalls/sys_enter_connect", "")?;

        Ok(())
    }

    pub fn attach_lsm(&mut self) -> anyhow::Result<()> {
        let btf = Btf::from_sys_fs()?;
        let program: &mut Lsm = self
            .bpf
            .program_mut("bprm_check")
            .ok_or_else(|| anyhow::anyhow!("Program 'bprm_check' not found"))?
            .try_into()?;

        program.load("bprm_check_security", &btf)?;
        let link_id = program.attach()?;
        self.lsm_links.insert("bprm_check".into(), link_id);

        Ok(())
    }

    pub fn add_kernel_rules(&mut self, rules: &[openxdr_common::KernelRule]) -> anyhow::Result<()> {
        let map = self
            .bpf
            .map_mut("RULES")
            .ok_or_else(|| anyhow::anyhow!("Map 'RULES' not found"))?;
        let mut hash_map: aya::maps::HashMap<_, u32, KernelRuleWrapper> =
            aya::maps::HashMap::try_from(map)?;

        for (i, rule) in rules.iter().enumerate() {
            hash_map.insert(i as u32, KernelRuleWrapper(*rule), 0)?;
        }
        Ok(())
    }
}
