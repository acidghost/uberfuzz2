use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
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


// format is time,fuzzer_ids,winning
fn parse_line(line: &String) -> Result<(u64, &str, Vec<&str>), String> {
    let splitted: Vec<_> = line.split(LOG_LINE_SEPARATOR).collect();
    if splitted.len() != 3 {
        return Err(format!("line '{}' does not have 3 columns", line));
    }

    let time_millis: u64 = splitted[0].parse().map_err(|e| {
        format!("failed parsing time from '{}': {}", line, e)
    })?;
    let fuzzer_id = splitted[1].trim();
    let winning_ids: Vec<_> = splitted[2].trim().split("_").collect();

    Ok((time_millis, fuzzer_id, winning_ids))
}


fn log_line(time_str: &str, fuzzer_ids: &[String], hash: &HashMap<String, u64>,
            mut file: &File, filename: &Path)
    -> Result<(), String>
{
    let log_str = time_str.to_string()
        + &fuzzer_ids.iter().map(|f| hash.get(f).unwrap().to_string())
            .collect::<Vec<_>>().join(SEPARATOR) + "\n";

    file.write_all(log_str.as_bytes()).map_err(|e| {
        format!("failed to write to {}: {}", filename.to_string_lossy(), e)
    })
}


fn process_file<P>(filename: P, accepted_filename: P, won_filename: P, time_unit: Option<u64>)
    -> Result<(), String>
    where P: AsRef<Path>
{
    let filename = filename.as_ref();
    let file = File::open(filename).map_err(|e| {
        format!("failed to open {}: {}", filename.to_string_lossy(), e)
    })?;

    let fuzzer_ids = find_fuzzer_ids(&file, &|line| parse_line(line).map(|t| t.1))?;
    let header_str = get_header(&fuzzer_ids);

    let accepted_filename = accepted_filename.as_ref();
    let accepted_file = init_output_file(accepted_filename, &header_str)?;

    let won_filename = won_filename.as_ref();
    let won_file = init_output_file(won_filename, &header_str)?;

    let mut accepted: HashMap<String, u64> = HashMap::new();
    let mut won: HashMap<String, u64> = HashMap::new();
    for fuzzer_id in &fuzzer_ids {
        accepted.insert(fuzzer_id.clone(), 0);
        won.insert(fuzzer_id.clone(), 0);
    }

    let mut last_time = 0u64;

    {
        let zeros_str = get_zeros(fuzzer_ids.len());
        let write_zeros = |mut file: &File, filename: &Path| {
            file.write_all(zeros_str.as_bytes()).map_err(|e| {
                format!("failed to write to {}: {}", filename.to_string_lossy(), e)
            })
        };
        write_zeros(&accepted_file, accepted_filename)?;
        write_zeros(&won_file, won_filename)?;
    }

    for line_result in BufReader::new(file).lines() {
        let line = line_result.map_err(|e| {
            format!("failed reading {}: {}", filename.to_string_lossy(), e)
        })?;

        let (time_millis, fuzzer_id, winning_ids) = parse_line(&line)?;

        {   // limit life of accepted borrow
            let mut fuzz_accepted = accepted.get_mut(fuzzer_id).unwrap();
            *fuzz_accepted += 1;
        }

        for fuzzer_id in &fuzzer_ids {
            if winning_ids.contains(&fuzzer_id.as_str()) {
                let mut fuzz_won = won.get_mut(fuzzer_id).unwrap();
                *fuzz_won += 1;
            }
        }

        // log according to time_unit
        if time_unit.is_none() || time_millis - last_time > time_unit.unwrap() {
            let this_time_unit = time_unit.map(|t| time_millis / t);
            let time_str = get_time_part(this_time_unit, time_millis);

            log_line(&time_str, &fuzzer_ids, &accepted, &accepted_file, accepted_filename)?;
            log_line(&time_str, &fuzzer_ids, &won, &won_file, won_filename)?;

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
    opts.optopt("f", "file", "The winning.log file to analyze",
        format!("{}/winning.log", WORK_PATH).as_str());
    opts.optopt("t", "time-unit", "The time unit to use to sample data", "1000");
    opts.optopt("a", "accepted", "Where to output the accepted inputs",
        format!("{}/accepted.log", WORK_PATH).as_str());
    opts.optopt("w", "won", "Where to output won inputs counts",
        format!("{}/won.log", WORK_PATH).as_str());

    let args: Vec<_> = env::args().collect();
    let matches = opts.parse(&args[1..]).map_err(|f| f.to_string()).unwrap();

    if matches.opt_present("h") || !matches.opt_present("f") ||
        !matches.opt_present("a") || !matches.opt_present("w")
    {
        println!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
        return;
    }

    let time_unit = matches.opt_str("t").map(|s| s.parse().unwrap());
    let filename = matches.opt_str("f").unwrap();
    let accepted_filename = matches.opt_str("a").unwrap();
    let won_filename = matches.opt_str("w").unwrap();

    if let Err(e) = process_file(&filename, &accepted_filename, &won_filename, time_unit) {
        error!("{}", e);
        exit(1);
    }
}
