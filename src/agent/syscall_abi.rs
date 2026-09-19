
use std::fs;

use openxdr_common::AbiOffsets;

/**
 * Tracepoint format is a kernel ABI that can change between kernel versions and architectures.
 * This struct is used to parse the tracepoint format and provide offsets for fields of interest.
 * @param name: The name of the tracepoint (e.g.,"sys_enter_execve").
 * @param fields: A vector of tuples containing field names, offsets, and sizes.

 */
#[derive(Debug, Clone)]
pub struct TracepointFormat {
    pub name: String,
    fields: Vec<(String, u16, u16)>,   // (field name, offset, size)
}

/**
 * Tracepoint format reads the tracepoint format from the kernel and provides offsets for fields of interest.
 * This is used to perform a lookup on the offsets of tps 
 * @func read: Reads the tracepoint format from the kernel and returns a TracepointFormat struct if successful.
 * @func parse: Parses the tracepoint format from a string and returns a TracepointFormat
 * @func offset_of: Returns the offset of a field in the tracepoint format if it exists.
 */
#[allow(dead_code)]
impl TracepointFormat {
    /**
     * Reads the tracepoint format from the kernel and returns a TracepointFormat struct if successful.
     * @param tp: The name of the tracepoint (e.g., "syscalls
     * @returns: Option<TracepointFormat> if successful, None otherwise.
     */

    pub fn read(tp: &str) -> Result<Self, String> {
        let mut parse_error = None;
        for base in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
            let path = format!("{}/events/syscalls/{}/format", base, tp);
            if let Ok(text) = fs::read_to_string(&path) {
                match Self::parse(&text) {
                    Ok(format) => return Ok(format),
                    Err(error) => {
                        parse_error = Some(format!(
                            "Tracepoint format for {} is unreadable: {} ({})",
                            tp, error, path
                        ));
                    }
                }
            }
        }
        Err(parse_error.unwrap_or_else(|| format!(
            "Tracepoint format for {} not found in tracefs",
            tp
        )))
    }
    /**
     * Parses the tracepoint format from a string and returns a TracepointFormat struct if successful.
     * @param text: The tracepoint format as a string.
     * @returns: Result<TracepointFormat, String> if successful, Err otherwise.
     */
    pub fn parse(text: &str) -> Result<Self,String> {
        let mut fields = Vec::new();
        let mut name = "";
        let tp_name: &str = text.lines().next().unwrap_or("").trim_start_matches("name:").trim();
        if tp_name.is_empty() {
            return Err("Tracepoint format missing name".to_string());
        }
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("field:") {
                continue;
            }
            let mut parts: Vec<&str> = line.split(";").collect();
            if parts.len() < 3 {
                continue;
            }
            parts[0] = parts[0].trim().trim_start_matches("field:");
            // now i have the c declaration of the first field which contains the type and name of the field
            //cleanup name of the field
            name = parts[0].trim().split_whitespace().last().unwrap_or("").trim_start_matches("*").split("[").next().unwrap_or("");
            let offset =parts.get(1)
                .and_then(|p| p.split_whitespace().last())
                .map(|s| {
                    s.trim_start_matches("offset:")
                    .trim_matches(|c: char| c.is_whitespace() || c == ',' || c == ';') // Cleans up trailing fluff
                })
                .ok_or_else(|| "Missing offset field in parts".to_string())? 
                .parse::<u16>()
                .map_err(|e| format!("Failed to parse offset: {e}"))?;
            let size = parts.get(2)
                .and_then(|p| p.split_whitespace().last())
                .map(|s| {
                    s.trim_start_matches("size:")
                    .trim_matches(|c: char| c.is_whitespace() || c == ',' || c == ';') // Cleans up trailing fluff
                })
                .ok_or_else(|| "Missing size field in parts".to_string())? 
                .parse::<u16>()
                .map_err(|e| format!("Failed to parse offset: {e}"))?;
        
            fields.push((name.to_string(), offset, size));
        }
        if fields.is_empty() {
            return Err(format!("no fields parsed for {}", name));
        }
        Ok(Self { name: tp_name.to_string(), fields })
        
    }
    /**
     * Returns the offset of a field in the tracepoint format if it exists.
     * @param field: The name of the field to look up.
     * @returns: Option<(u16, u16)> containing the offset and size of the field if it exists, None otherwise.
     */
     pub fn offset_of(&self, field: &str) -> Option<(u16, u16)> {
        self.fields.iter()
            .find(|(n, _, _)| n == field)
            .map(|(_, off, size)| (*off, *size))
    }
    /**
     * Returns the base offset of the first non-common field in the tracepoint format.
     * @returns: Option<u16> containing the base offset of the first non-common field if it exists, None otherwise.
     * This is used to determine the base offset for syscall arguments
     */
    pub fn arg_base(&self) -> Option<u16> {
        self.fields.iter()
            .find(|(n, _, _)| !n.starts_with("common_") && n != "__syscall_nr")
            .map(|(_, off, _)| *off)
    }
}


pub const ARG_BASE_DEFAULT: u16 = 16;
pub const fn sys_arg(n: u16) -> u16 { ARG_BASE_DEFAULT + 8 * n }

#[derive(Debug, Clone)]
pub struct SyscallAbi {
    pub execve_filename:    u32,
    pub execveat_filename:  u32,
    pub open_filename:      u32,
    pub open_flags:         u32,
    pub openat_filename:    u32,
    pub openat_flags:       u32,
    pub connect_fd:         u32,
    pub connect_addr:       u32,

    /// Availability, not offsets -- drives which probes we attach.
    pub has_open: bool,
    pub discovered: bool,

    /// Every field that fell back, and why. Printed at startup.
    pub diagnostics: Vec<String>,
}

impl SyscallAbi {
    /// Reads tracefs, validates, falls back to `16 + 8n` per field.
    pub fn discover() -> Self {
        let mut abi = Self::arithmetic_default();
        let mut diagnostics = Vec::new();

        let tracepoints: Vec<String> = vec![
        "sys_enter_execve".to_string(),
        "sys_enter_execveat".to_string(),
        "sys_enter_open".to_string(),
        "sys_enter_openat".to_string(),
        "sys_enter_connect".to_string()
        ];
        abi.has_open = false;

        for tp in tracepoints {
            match TracepointFormat::read(&tp) {
                Ok(fmt) => {
                let fmt_opt = Some(fmt.clone());
                match tp.as_str() {
                "sys_enter_execve" => {
                        abi.execve_filename = resolve(&fmt_opt, "filename", sys_arg(0), &mut diagnostics);
                    }
                "sys_enter_execveat" => {
                        abi.execveat_filename = resolve(&fmt_opt, "filename", sys_arg(1), &mut diagnostics);
                    }
                "sys_enter_open" => {
                        abi.open_filename = resolve(&fmt_opt, "filename", sys_arg(0), &mut diagnostics);
                        abi.open_flags = resolve(&fmt_opt, "flags", sys_arg(1), &mut diagnostics);
                        abi.has_open = true;
                    }
                "sys_enter_openat" => {
                        abi.openat_filename = resolve(&fmt_opt, "filename", sys_arg(1), &mut diagnostics);
                        abi.openat_flags = resolve(&fmt_opt, "flags", sys_arg(2), &mut diagnostics);
                    }
                "sys_enter_connect" => {
                        abi.connect_fd = resolve(&fmt_opt, "fd", sys_arg(0), &mut diagnostics);
                        abi.connect_addr = resolve(&fmt_opt, "uservaddr", sys_arg(1), &mut diagnostics);
                    }
                    _ => {}
                }
                abi.discovered = true;
                }
                Err(error) => {
                    diagnostics.push(format!("{}, using fallback offsets.", error));
                }
            }
        }
        abi.diagnostics = diagnostics;
        abi

    }
    /// Compile-time arithmetic only. Used when tracefs is unavailable.
    pub fn arithmetic_default() -> Self {
        return Self {
            execve_filename:    sys_arg(0) as u32,
            execveat_filename:  sys_arg(1) as u32,
            open_filename:      sys_arg(0) as u32,
            open_flags:         sys_arg(1) as u32,
            openat_filename:    sys_arg(1) as u32,
            openat_flags:       sys_arg(2) as u32,
            connect_fd:         sys_arg(0) as u32,
            connect_addr:       sys_arg(1) as u32,

            has_open: false,
            discovered: false,

            diagnostics: Vec::new(),
        };
    }

    pub fn report(&self) {
        println!("Syscall ABI: {}",
        if self.discovered { "discovered from tracefs" }
            else { "ARITHMETIC FALLBACK (tracefs unreadable) - assuming current ABI" });
        println!("  execve.filename    {}", self.execve_filename);
        println!("  execveat.filename  {}", self.execveat_filename);
        println!("  open.filename      {}", self.open_filename);
        println!("  openat.filename    {}", self.openat_filename);
        println!("  openat.flags       {}", self.openat_flags);
        println!("  connect.fd         {}", self.connect_fd);
        println!("  connect.uservaddr  {}", self.connect_addr);
        println!("  sys_enter_open     {}",
            if self.has_open { "present" } else { "absent (expected on aarch64)" });
        for d in &self.diagnostics {
            println!("  ! {}", d);
        }
    }

    pub fn return_offset_struct(&self) -> AbiOffsets {
        let offsets = AbiOffsets {
            execve_filename:    self.execve_filename,
            execveat_filename:  self.execveat_filename,
            open_filename:      self.open_filename,
            open_flags:         self.open_flags,
            openat_filename:    self.openat_filename,
            openat_flags:       self.openat_flags,
            connect_fd:         self.connect_fd,
            connect_addr:       self.connect_addr,
        };
        offsets
    }
}


/// Validate one discovered offset, falling back if it looks wrong.
/// Bounds are from Part 3 (amended) - note `base` comes from the FILE.
fn resolve(
    fmt: &Option<TracepointFormat>,
    field: &str,
    fallback: u16,
    diags: &mut Vec<String>,
) -> u32 {
    // YOU WRITE THIS:
    //   1. no format file          -> fallback, push a diagnostic
    //   2. field missing           -> fallback, push a diagnostic
    //   3. let base = fmt.arg_base()
    //      reject unless: offset >= base
    //                     offset <= base + 8*5
    //                     (offset - base) % 8 == 0
    //                     size == 8
    //   4. if the accepted value != fallback, push a diagnostic saying so.
    //      That disagreement is the single most important thing this
    //      feature can tell you - do not swallow it.
    if field.is_empty() {
        diags.push(format!("Field name is empty, using fallback offset {}", fallback));
        return fallback as u32;
    }
    let fmt = match fmt {
        Some(f) => f,
        None => {
            diags.push(format!("Tracepoint format not found, using fallback offset {}", fallback));
            return fallback as u32;
        }
    };
    let (offset, size) = match fmt.offset_of(field) {
        Some((off, sz)) => (off, sz),
        None => {
            diags.push(format!("Field '{}' not found in tracepoint format, using fallback offset {}",
                field, fallback));
            return fallback as u32;
        }
    };
    let base = match fmt.arg_base() {
        Some(b) => b,
        None => {
            diags.push(format!("No argument base found in tracepoint format, using fallback offset {}",
                fallback));
            return fallback as u32;
        }
    };
    if offset < base || offset > base + 8 * 5 || (offset - base) % 8 != 0 || size != 8 {
        diags.push(format!("
Field '{}' has invalid offset {} or size {}, using fallback offset {}",
            field, offset, size, fallback));
        return fallback as u32;
    }
    if offset != fallback {
        diags.push(format!("Field '{}' has offset {} which differs from fallback {}, using discovered offset",
            field, offset, fallback));
    }
    offset as u32
    
}

// ---------------------------------------------------------------------------
// Tests written against the SPECIFICATION in
// docs/abi_discovery/08_syscall_abi_lab_1.md — not against this implementation.
// A failing test means the code disagrees with the lab, not that the test is
// wrong. Fixing is the developer's call.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // Real capture, aarch64 kernel 6.10.14-linuxkit. Tabs are explicit so no
    // editor can silently reformat the fixture out from under the test.
    const OPENAT_AARCH64: &str = concat!(
        "name: sys_enter_openat\n",
        "ID: 731\n",
        "format:\n",
        "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n",
        "\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n",
        "\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n",
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
        "\n",
        "\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n",
        "\tfield:int dfd;\toffset:16;\tsize:8;\tsigned:0;\n",
        "\tfield:const char * filename;\toffset:24;\tsize:8;\tsigned:0;\n",
        "\tfield:int flags;\toffset:32;\tsize:8;\tsigned:0;\n",
        "\tfield:umode_t mode;\toffset:40;\tsize:8;\tsigned:0;\n",
        "\n",
        "print fmt: \"dfd: 0x%08lx, filename: 0x%08lx\"\n",
    );

    // Real capture, aarch64. Exercises `const char *const * argv`.
    const EXECVE_AARCH64: &str = concat!(
        "name: sys_enter_execve\n",
        "format:\n",
        "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n",
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
        "\n",
        "\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n",
        "\tfield:const char * filename;\toffset:16;\tsize:8;\tsigned:0;\n",
        "\tfield:const char *const * argv;\toffset:24;\tsize:8;\tsigned:0;\n",
        "\tfield:const char *const * envp;\toffset:32;\tsize:8;\tsigned:0;\n",
    );

    // Real capture, aarch64. Field is `uservaddr`, and its type is a struct ptr.
    const CONNECT_AARCH64: &str = concat!(
        "name: sys_enter_connect\n",
        "format:\n",
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
        "\n",
        "\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n",
        "\tfield:int fd;\toffset:16;\tsize:8;\tsigned:0;\n",
        "\tfield:struct sockaddr * uservaddr;\toffset:24;\tsize:8;\tsigned:0;\n",
        "\tfield:int addrlen;\toffset:32;\tsize:8;\tsigned:0;\n",
    );

    // SYNTHETIC, not captured — derived from the kernel signature
    // SYSCALL_DEFINE3(open, const char __user *filename, int flags, umode_t mode).
    // Replace with a real x86_64 capture (lab Step 8) when one is available.
    // This is the layout the entire `open_enter` bug fix depends on.
    const OPEN_X86_64_SYNTHETIC: &str = concat!(
        "name: sys_enter_open\n",
        "format:\n",
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
        "\n",
        "\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n",
        "\tfield:const char * filename;\toffset:16;\tsize:8;\tsigned:0;\n",
        "\tfield:int flags;\toffset:24;\tsize:8;\tsigned:0;\n",
        "\tfield:umode_t mode;\toffset:32;\tsize:8;\tsigned:0;\n",
    );

    // -- parser ------------------------------------------------------------

    #[test]
    fn parse_extracts_the_bare_field_name_not_the_declaration() {
        // Spec, Part 1 "the one genuinely fiddly bit": the name is the LAST
        // whitespace-separated token of the declaration, with `*` and `[N]`
        // stripped. `const char * filename` must yield `filename`.
        let fmt = TracepointFormat::parse(OPENAT_AARCH64).expect("should parse");
        let names: Vec<&str> = fmt.fields.iter().map(|(n, _, _)| n.as_str()).collect();
        

        assert!(
            names.contains(&"filename"),
            "expected a field literally named `filename`, got {:?}",
            names
        );
    }

    #[test]
    fn parse_handles_every_declaration_shape_in_the_spec_table() {
        let openat = TracepointFormat::parse(OPENAT_AARCH64).expect("openat parses");
        let execve = TracepointFormat::parse(EXECVE_AARCH64).expect("execve parses");
        let connect = TracepointFormat::parse(CONNECT_AARCH64).expect("connect parses");

        // `int dfd`                    -> dfd
        assert_eq!(openat.offset_of("dfd").map(|(o, _)| o), Some(16));
        // `const char * filename`      -> filename
        assert_eq!(openat.offset_of("filename").map(|(o, _)| o), Some(24));
        // `umode_t mode`               -> mode
        assert_eq!(openat.offset_of("mode").map(|(o, _)| o), Some(40));
        // `const char *const * argv`   -> argv
        assert_eq!(execve.offset_of("argv").map(|(o, _)| o), Some(24));
        // `struct sockaddr * uservaddr`-> uservaddr
        assert_eq!(connect.offset_of("uservaddr").map(|(o, _)| o), Some(24));
    }

    #[test]
    fn arg_base_is_16_on_every_kernel_shipping_today() {
        // Spec Part 3 (amended): base is the first field that is neither
        // `common_*` nor `__syscall_nr`. For openat that is `dfd` at 16.
        let fmt = TracepointFormat::parse(OPENAT_AARCH64).expect("should parse");
        assert_eq!(fmt.arg_base(), Some(16), "arg_base must skip the trace_entry header and __syscall_nr");
    }

    #[test]
    fn arg_base_follows_a_shifted_header_rather_than_assuming_16() {
        // The whole point of the Q3 amendment: if trace_entry ever grows,
        // base must move with it. Synthetic future kernel, args start at 24.
        let shifted = concat!(
            "name: sys_enter_openat\n",
            "format:\n",
            "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
            "\tfield:int common_future;\toffset:12;\tsize:4;\tsigned:1;\n",
            "\tfield:int __syscall_nr;\toffset:16;\tsize:4;\tsigned:1;\n",
            "\tfield:int dfd;\toffset:24;\tsize:8;\tsigned:0;\n",
            "\tfield:const char * filename;\toffset:32;\tsize:8;\tsigned:0;\n",
        );
        let fmt = TracepointFormat::parse(shifted).expect("should parse");
        assert_eq!(fmt.arg_base(), Some(24));
    }

    #[test]
    fn parse_records_the_tracepoint_name_not_a_field_name() {
        // `TracepointFormat.name` is documented as "the name of the
        // tracepoint". The format file's first line supplies it.
        let fmt = TracepointFormat::parse(OPENAT_AARCH64).expect("should parse");
        assert_eq!(fmt.name, "sys_enter_openat");
    }

    #[test]
    fn parse_rejects_input_with_no_fields() {
        assert!(TracepointFormat::parse("").is_err());
        assert!(TracepointFormat::parse("name: sys_enter_openat\nID: 731\n").is_err());
    }

    #[test]
    fn parse_survives_a_truncated_file() {
        // tracefs reads can come back short. One good field then a cut line
        // must not lose the good field.
        let truncated = concat!(
            "name: sys_enter_openat\n",
            "format:\n",
            "\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;\n",
            "\tfield:int dfd;\toffset:16;\tsize:8;\tsigned:0;\n",
            "\tfield:const char * filen",
        );
        let fmt = TracepointFormat::parse(truncated).expect("partial file still yields fields");
        assert_eq!(fmt.offset_of("dfd").map(|(o, _)| o), Some(16));
    }

    // -- resolve() validation ----------------------------------------------

    #[test]
    fn resolve_returns_the_discovered_offset_when_it_is_valid() {
        let fmt = Some(TracepointFormat::parse(OPENAT_AARCH64).expect("parses"));
        let mut d = Vec::new();
        assert_eq!(resolve(&fmt, "filename", sys_arg(1), &mut d), 24);
    }

    #[test]
    fn resolve_falls_back_when_the_field_is_absent_and_says_so() {
        let fmt = Some(TracepointFormat::parse(OPENAT_AARCH64).expect("parses"));
        let mut d = Vec::new();
        assert_eq!(resolve(&fmt, "no_such_field", 24, &mut d), 24);
        assert!(!d.is_empty(), "a silent fallback is the failure mode this feature exists to prevent");
    }

    #[test]
    fn resolve_rejects_a_non_eight_byte_slot() {
        // `common_pid` is size 4. Spec Part 3 requires size == 8, because a
        // narrow slot means we are not looking at a syscall argument at all.
        let fmt = Some(TracepointFormat::parse(OPENAT_AARCH64).expect("parses"));
        let mut d = Vec::new();
        assert_eq!(resolve(&fmt, "common_pid", 16, &mut d), 16, "must reject and fall back");
        assert!(!d.is_empty());
    }

    #[test]
    fn resolve_reports_disagreement_with_the_arithmetic_default() {
        // Spec Part 3: "if the accepted value != fallback, push a diagnostic.
        // That disagreement is the single most important thing this feature
        // can tell you - do not swallow it."
        let fmt = Some(TracepointFormat::parse(OPENAT_AARCH64).expect("parses"));
        let mut d = Vec::new();
        // Deliberately pass the WRONG default (open's arg0) for openat's filename.
        let got = resolve(&fmt, "filename", sys_arg(0), &mut d);
        assert_eq!(got, 24, "discovered value wins");
        assert!(!d.is_empty(), "the disagreement must be reported, not swallowed");
    }

    // -- the bug this whole feature exists to prevent -----------------------

    #[test]
    fn open_and_openat_resolve_to_different_offsets() {
        // This is the `open_enter` bug, encoded. open(filename,flags,mode) has
        // filename at 16; openat(dfd,filename,flags,mode) has it at 24. Any
        // implementation that returns the same answer for both reintroduces
        // silent detection loss on x86_64.
        let open = Some(TracepointFormat::parse(OPEN_X86_64_SYNTHETIC).expect("parses"));
        let openat = Some(TracepointFormat::parse(OPENAT_AARCH64).expect("parses"));
        let mut d = Vec::new();

        assert_eq!(resolve(&open, "filename", sys_arg(0), &mut d), 16, "open.filename");
        assert_eq!(resolve(&open, "flags", sys_arg(1), &mut d), 24, "open.flags");
        assert_eq!(resolve(&openat, "filename", sys_arg(1), &mut d), 24, "openat.filename");
        assert_eq!(resolve(&openat, "flags", sys_arg(2), &mut d), 32, "openat.flags");
    }

    // -- SyscallAbi state flags --------------------------------------------

    #[test]
    fn arithmetic_default_must_not_claim_open_exists() {
        // `has_open` is a discovered property. Defaulting it to true asserts a
        // fact we have not established, and on aarch64 it is false. Lab Q4/Q5:
        // availability must never be assumed.
        let abi = SyscallAbi::arithmetic_default();
        assert!(!abi.discovered);
        assert!(!abi.has_open, "arithmetic_default() cannot know that sys_enter_open exists");
    }

    #[test]
    fn discover_sets_discovered_true_when_any_tracepoint_was_read() {
        // On macOS no tracefs exists, so this must report the fallback path
        // honestly. On Linux it must report success. Either way `discovered`
        // has to reflect reality rather than being permanently false.
        let abi = SyscallAbi::discover();
        if cfg!(target_os = "linux") {
            assert!(abi.discovered, "tracefs is readable on Linux; discovered must be true");
        } else {
            assert!(!abi.discovered);
            assert!(!abi.diagnostics.is_empty(), "fallback must be explained, never silent");
        }
    }
}
