use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::process::exit;
use std::time;
use std::thread;
use std::sync::mpsc;

extern crate glob;
use glob::glob;

extern crate getopts;
use getopts::Options;

mod coverage;
use coverage::{Branch, read_structs};


fn usage(prog_name: &str, opts: &Options, code: i32) {
    println!("{}", opts.usage(&format!("Usage: {} [options]", prog_name)));
    exit(code);
}

fn main() {
    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help");
    opts.optopt("g", "glob", "Glob-style pattern",
        "./work/stored_work/objdump-mono-24h-afhv-01/{{fuzzer}}/driver/*.coverage");
    opts.optmulti("f", "fuzzer", "Fuzzer to use", "honggfuzz");
    opts.optopt("t", "timesteps", "Number of timesteps in runs", "480");

    let args: Vec<_> = env::args().collect();
    let matches = opts.parse(&args[1..]).unwrap();

    let required_opts = ["g".to_string(), "t".to_string(), "f".to_string()];
    let opt_exit_code = if matches.opt_present("h") { Some(0) }
        else if !matches.opts_present(&required_opts) { Some(1) }
        else { None };

    if let Some(code) = opt_exit_code {
        usage(&args[0], &opts, code);
    }

    let glob_pattern = matches.opt_str("g").unwrap();
    let timesteps: usize = matches.opt_str("t").unwrap().parse().unwrap();
    let fuzzers = matches.opt_strs("f");

    let mut coverage_map: HashMap<String, BTreeMap<u64, HashSet<Branch>>> = HashMap::new();
    let (tx, rx) = mpsc::channel();

    for fuzzer in fuzzers.clone() {
        let tx = tx.clone();
        let glob_pattern_f = glob_pattern.replace("{{fuzzer}}", &fuzzer);
        thread::spawn(move || {
            let mut fuzzer_coverage_map: BTreeMap<u64, HashSet<Branch>> = BTreeMap::new();
            let mut fuzzer_coverage_set: HashSet<Branch> = HashSet::new();

            for entry in glob(&glob_pattern_f).unwrap() {
                let entry = entry.unwrap();
                let meta = match fs::metadata(&entry) {
                    Ok(m) => m,
                    Err(e) => {
                        println!("Failed to get metadata from {}: {}", entry.display(), e.to_string());
                        exit(1);
                    }
                };

                let creation_time = match meta.modified() {
                    Ok(c) => c,
                    Err(e) => {
                        println!("Failed to get time from {}: {}", entry.display(), e.to_string());
                        exit(1);
                    }
                };

                let coverage: Vec<Branch> = read_structs(&entry).unwrap();
                fuzzer_coverage_set.extend(coverage);

                let minutes_since_epoch = creation_time.duration_since(time::UNIX_EPOCH)
                    .unwrap().as_secs() / 60;

                if fuzzer_coverage_map.contains_key(&minutes_since_epoch) {
                    let existing_set = fuzzer_coverage_map.get_mut(&minutes_since_epoch).unwrap();
                    existing_set.extend(&fuzzer_coverage_set);
                } else {
                    fuzzer_coverage_map.insert(minutes_since_epoch, fuzzer_coverage_set.clone());
                }
            }

            tx.send((fuzzer.clone(), fuzzer_coverage_map)).unwrap();
        });
    }

    for _ in 0..fuzzers.len() {
        let received = rx.recv().unwrap();
        coverage_map.insert(received.0, received.1);
    }

    let min_time = coverage_map.values().flat_map(|fcm| fcm.keys()).min().unwrap().clone();
    let mut coverage: usize = 0;

    for t in 0..timesteps {
        let mut set: HashSet<Branch> = HashSet::new();
        for fuzzer in &fuzzers {
            let fuzzer_coverage_map = coverage_map.get(fuzzer).unwrap();
            let tidx = t as u64 + min_time;
            if let Some(fset) = fuzzer_coverage_map.get(&tidx) {
                set.extend(fset);
            }
        }

        let set_len = set.len();
        if set_len > coverage {
            coverage = set_len;
        }

        println!("{} {}", t, coverage);
    }
}
