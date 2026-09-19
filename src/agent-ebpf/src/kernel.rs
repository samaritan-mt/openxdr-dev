use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::{Lsm, TracePoint},
    Btf, Ebpf, EbpfLoader
};
use std::{
    collections::HashMap,
    convert::TryFrom,
};
use openxdr_common::{AbiOffsets};


#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct KernelRuleWrapper(openxdr_common::KernelRule);

unsafe impl aya::Pod for KernelRuleWrapper {}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct KernelRuleArrayWrapper(openxdr_common::KernelRuleArray);

unsafe impl aya::Pod for KernelRuleArrayWrapper {}

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
    pub fn new(data: &[u8], abi: &AbiOffsets) -> anyhow::Result<Self> {
        let bpf = EbpfLoader::new()
        .set_global("EXECVE_FILENAME_OFF",   &abi.execve_filename,   true)
        .set_global("EXECVEAT_FILENAME_OFF", &abi.execveat_filename, true)
        .set_global("OPEN_FILENAME_OFF",     &abi.open_filename,     true)
        .set_global("OPEN_FLAGS_OFF",        &abi.open_flags,        true)
        .set_global("OPENAT_FILENAME_OFF",   &abi.openat_filename,   true)
        .set_global("OPENAT_FLAGS_OFF",      &abi.openat_flags,      true)
        .set_global("CONNECT_FD_OFF",        &abi.connect_fd,        true)
        .set_global("CONNECT_ADDR_OFF",      &abi.connect_addr,      true)
        .load(data)?;


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

    pub fn attach_file_monitoring(&mut self, has_open: bool, discovered: bool) -> anyhow::Result<()> {
         if has_open {
        // attach as today; a failure here is now a REAL error
            let program_open: &mut TracePoint = self
            .bpf
            .program_mut("open_enter")
            .ok_or_else(|| anyhow::anyhow!("Program 'open_enter' not found"))?
            .try_into()?;
            program_open.load()?;
            let link_result = program_open.attach("syscalls/sys_enter_open", "")?;    
        } else if discovered && cfg!(target_arch = "x86_64") {
            anyhow::bail!("sys_enter_open missing on x86_64 - coverage hole");
        } else {
            println!("Notice: sys_enter_open absent (expected on aarch64)");
        }

        

        let program_openat: &mut TracePoint = self
            .bpf
            .program_mut("openat_enter")
            .ok_or_else(|| anyhow::anyhow!("Program 'openat_enter' not found"))?
            .try_into()?;
        program_openat.load()?;
        let link_id_at = program_openat.attach("syscalls/sys_enter_openat", "")?;
        self.links.insert("openat_enter".into(), link_id_at);

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

    /// Upload the compiled rule set as a single `Array` map value.
    ///
    /// `permissive_mask` carries the event types the kernel must forward
    /// unconditionally; it is computed by the engine, which is the only place
    /// that knows which Sigma constructs failed to lower.
    pub fn add_kernel_rules(
        &mut self,
        rules: &[openxdr_common::KernelRule],
        permissive_mask: u32,
    ) -> anyhow::Result<()> {
        if rules.len() > openxdr_common::MAX_KERNEL_RULES {
            anyhow::bail!(
                "engine produced {} kernel rules, budget is {}",
                rules.len(),
                openxdr_common::MAX_KERNEL_RULES
            );
        }

        let map = self
            .bpf
            .map_mut("RULES_ARRAY")
            .ok_or_else(|| anyhow::anyhow!("Map 'RULES_ARRAY' not found"))?;
        let mut array_map: aya::maps::Array<_, KernelRuleArrayWrapper> =
            aya::maps::Array::try_from(map)?;

        let mut block = openxdr_common::KernelRuleArray {
            count: rules.len() as u32,
            permissive_mask,
            rules: [openxdr_common::KernelRule {
                event_type: 0,
                check_comm: 0,
                comm_kind: 0,
                comm_len: 0,
                check_path: 0,
                path_kind: 0,
                path_len: 0,
                _pad: 0,
                comm: [0; 16],
                path: [0; openxdr_common::MAX_PATTERN_LEN],
            }; openxdr_common::MAX_KERNEL_RULES],
        };

        block.rules[..rules.len()].copy_from_slice(rules);

        array_map.set(0, KernelRuleArrayWrapper(block), 0)?;
        Ok(())
    }
}
