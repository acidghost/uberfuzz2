use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::ops::Add;
use std::process::exit;

extern crate pretty_env_logger;
#[macro_use] extern crate log;

extern crate getopts;
use getopts::Options;

#[path="../common.rs"]
mod common_m;
use common_m::{LOG_LINE_SEPARATOR, WORK_PATH};

mod common;
use common::*;

mod coverage;
use coverage::{Branch, read_structs};


type BranchCounts = HashMap<Branch, usize>;


// format is time,fuzzer_ids,input_path,coverage_path
fn parse_line(line: &String) -> Result<(u64, &str, &str, &str), String> {
    let splitted: Vec<_> = line.split(LOG_LINE_SEPARATOR).collect();
    if splitted.len() != 4 {
        return Err(format!("line '{}' has not 4 columns", line));
    }

    let time_millis: u64 = splitted[0].parse().map_err(|e| {
        format!("failed parsing time from '{}': {}", line, e)
    })?;
    let fuzzer_id = splitted[1].trim();
    let input_path = splitted[2].trim();
    let coverage_path = splitted[3].trim();

    Ok((time_millis, fuzzer_id, input_path, coverage_path))
}


fn process_file<P>(filename: P, coverage_filename: P, interesting_filename: P,
                   time_unit: Option<u64>) -> Result<(), String>
                   where P: AsRef<Path>
{
    let filename = filename.as_ref();
    let file = File::open(filename).map_err(|e| {
        format!("failed to open {}: {}", filename.to_string_lossy(), e)
    })?;

    let fuzzer_ids = find_fuzzer_ids(&file, &|line| Ok(parse_line(line)?.1))?;
    let header_str = format!("unit{sep}time{sep}{}{sep}global\n",
        fuzzer_ids.join(SEPARATOR), sep=SEPARATOR);

    let coverage_filename = coverage_filename.as_ref();
    let mut coverage_file = init_output_file(coverage_filename, &header_str)?;

    let interesting_filename = interesting_filename.as_ref();
    let mut interesting_file = init_output_file(interesting_filename, &header_str)?;

    let mut coverage: HashMap<String, BranchCounts> = HashMap::new();
    let mut interesting: HashMap<String, usize> = HashMap::new();
    for fuzzer_id in &fuzzer_ids {
        coverage.insert(fuzzer_id.clone(), HashMap::new());
        interesting.insert(fuzzer_id.clone(), 0);
    }

    let mut global_coverage: BranchCounts = HashMap::new();

    let mut global_interesting = 0usize;

    let mut last_time = 0u64;

    {
        let zeros_str = get_zeros(fuzzer_ids.len() + 1);
        let write_zeros = |mut file: &File, filename: &Path| {
            file.write_all(zeros_str.as_bytes()).map_err(|e| {
                format!("failed to write to {}: {}", filename.to_string_lossy(), e)
            })
        };
        write_zeros(&coverage_file, coverage_filename)?;
        write_zeros(&interesting_file, interesting_filename)?;
    }

    for line_result in BufReader::new(file).lines() {
        let line = line_result.map_err(|e| {
            format!("failed reading {}: {}", filename.to_string_lossy(), e)
        })?;

        let (time_millis, fuzzer_id, _, coverage_path) = parse_line(&line)?;

        let branches: Vec<Branch> = read_structs(&coverage_path).map_err(|e| {
            format!("failed to parse coverage from {}: {}", coverage_path, e)
        })?;

        {   // limit life of coverage borrow
            let mut fuzz_coverage = coverage.get_mut(fuzzer_id).unwrap();
            for branch in &branches {
                fuzz_coverage.entry(*branch).or_insert(0).add(1);
                global_coverage.entry(*branch).or_insert(0).add(1);
            }
        }

        {   // limit life of interesting borrow
            let mut fuzz_interesting = interesting.get_mut(fuzzer_id).unwrap();
            *fuzz_interesting += 1;
        }

        global_interesting += 1;

        // log according to time_unit
        if time_unit.is_none() || time_millis - last_time > time_unit.unwrap() {
            let this_time_unit = time_unit.map(|t| time_millis / t);
            let time_str = get_time_part(this_time_unit, time_millis);

            let coverage_str = time_str.clone()
                + &fuzzer_ids.iter().map(|f| format!("{}", coverage.get(f).unwrap().len()))
                    .collect::<Vec<_>>().join(SEPARATOR)
                + SEPARATOR + &global_coverage.len().to_string() + "\n";

            coverage_file.write_all(coverage_str.as_bytes()).map_err(|e| {
                format!("failed to write to {}: {}", coverage_filename.to_string_lossy(), e)
            })?;

            let interesting_str = time_str.clone()
                + &fuzzer_ids.iter().map(|f| format!("{}", interesting.get(f).unwrap()))
                    .collect::<Vec<_>>().join(SEPARATOR)
                + SEPARATOR + &global_interesting.to_string() + "\n";

            interesting_file.write_all(interesting_str.as_bytes()).map_err(|e| {
                format!("failed to write to {}: {}", interesting_filename.to_string_lossy(), e)
            })?;

            last_time = time_millis;
        }
    }

    Ok(())
}


fn main() {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "info");
    }

    pretty_env_logger::init().unwrap();

    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help");
    opts.optopt("f", "file", "The inputs.log file to analyze",
        format!("{}/inputs.log", WORK_PATH).as_str());
    opts.optopt("t", "time-unit", "The time unit to use to sample coverage", "1000");
    opts.optopt("c", "coverage", "Where to store coverage info",
        format!("{}/coverage.log", WORK_PATH).as_str());
    opts.optopt("i", "interesting", "Where to store interesting info",
        format!("{}/interesting.log", WORK_PATH).as_str());

    let args: Vec<_> = env::args().collect();
    let matches = opts.parse(&args[1..]).map_err(|f| f.to_string()).unwrap();

    if matches.opt_present("h") || !matches.opt_present("f") ||
        !matches.opt_present("i") || !matches.opt_present("c")
    {
        println!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
        return;
    }

    let time_unit = matches.opt_str("t").map(|s| s.parse().unwrap());
    let filename = matches.opt_str("f").unwrap();
    let coverage_filename = matches.opt_str("c").unwrap();
    let interesting_filename = matches.opt_str("i").unwrap();

    if let Err(e) = process_file(&filename, &coverage_filename, &interesting_filename, time_unit) {
        error!("{}", e);
        exit(1);
    }
}
