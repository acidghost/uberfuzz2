use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::mem;
use std::path::Path;
use std::slice;
use std::ops::Add;

extern crate pretty_env_logger;
#[macro_use] extern crate log;

extern crate getopts;
use getopts::Options;


#[repr(C)]
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct Branch {
    from: u64,
    to: u64
}

type BranchCounts = HashMap<Branch, usize>;


fn process_file<P: AsRef<Path>>(filename: P, time_unit: Option<u64>) -> Result<(), String> {
    let filename = filename.as_ref();
    let file = File::open(filename).map_err(|e| {
        format!("failed to open {}: {}", filename.to_string_lossy(), e)
    })?;

    let mut coverage: HashMap<String, BranchCounts> = HashMap::new();
    let mut last_time = 0u64;

    for line_result in BufReader::new(file).lines() {
        let line = line_result.map_err(|e| {
            format!("failed reading {}: {}", filename.to_string_lossy(), e)
        })?;

        // format is time,fuzzer_ids,input_path,coverage_path
        let splitted: Vec<_> = line.split(",").collect();
        if splitted.len() != 4 {
            warn!("line '{}' has not 4 columns", line);
            continue;
        }
        let time_millis: u64 = splitted[0].parse().map_err(|e| {
            format!("failed parsing time from '{}': {}", line, e)
        })?;
        let fuzzer_id = splitted[1].trim();
        // the input_path is unused for now
        // let input_path = splitted[2].trim();
        let coverage_path = splitted[3].trim();

        let branches: Vec<Branch> = read_structs(&coverage_path).map_err(|e| {
            format!("failed to parse coverage from {}: {}", coverage_path, e)
        })?;

        {   // limit life of coverage borrow
            let mut fuzz_coverage = coverage.entry(fuzzer_id.to_string()).or_insert(HashMap::new());
            for branch in &branches {
                fuzz_coverage.entry(*branch).or_insert(0).add(1);
            }
        }

        // log according to time_unit
        if time_unit.is_none() || time_millis - last_time > time_unit.unwrap() {
            info!("{} : {}", time_millis, coverage.iter().map(|t| {
                format!("{} {}", t.0, t.1.len())
            }).collect::<Vec<_>>().join(" - "));
            last_time = time_millis;
        }
    }

    Ok(())
}


fn read_structs<T, P: AsRef<Path>>(path: P) -> io::Result<Vec<T>> {
    let path = path.as_ref();
    let struct_size = mem::size_of::<T>();
    let num_bytes = fs::metadata(path)?.len() as usize;
    let num_structs = num_bytes / struct_size;
    let mut reader = BufReader::new(File::open(path)?);
    let mut r = Vec::<T>::with_capacity(num_structs);
    unsafe {
        let mut buffer = slice::from_raw_parts_mut(r.as_mut_ptr() as *mut u8, num_bytes);
        try!(reader.read_exact(buffer));
        r.set_len(num_structs);
    }
    Ok(r)
}


fn main() {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "info");
    }

    pretty_env_logger::init().unwrap();

    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help");
    opts.optopt("f", "file", "The inputs.log file to analyze", "./work/inputs.log");
    opts.optopt("t", "time-unit", "The time unit to use to sample coverage", "1000");

    let args: Vec<_> = env::args().collect();
    let matches = opts.parse(&args[1..]).map_err(|f| f.to_string()).unwrap();

    if matches.opt_present("h") || !matches.opt_present("f") {
        println!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
        return;
    }

    let time_unit = matches.opt_str("t").map(|s| s.parse().unwrap());

    if let Err(e) = process_file(&matches.opt_str("f").unwrap(), time_unit) {
        error!("{}", e);
    }
}
