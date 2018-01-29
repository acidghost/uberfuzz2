use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::PathBuf;
use std::process::exit;

extern crate glob;
use glob::glob;

extern crate getopts;
use getopts::Options;


fn parse_master_data(path: PathBuf, timesteps: usize) -> Result<Vec<u64>, String> {
    let file = File::open(&path).unwrap();

    let mut vector: Vec<u64> = Vec::with_capacity(timesteps + 1);
    let mut i = 0usize;
    let mut v = 0u64;

    for line_result in BufReader::new(file).lines().skip(1) {
        let line = line_result.unwrap();
        let splitted: Vec<_> = line.split(" ").collect();
        if splitted.len() < 2 {
            return Err(format!("Line in {} contains less than 2 items", path.display()));
        }
        let t: usize = splitted.first().unwrap().parse().unwrap();
        let cov: u64 = splitted.last().unwrap().parse().unwrap();
        loop {
            if i == t { break; }
            vector.push(v);
            i += 1;
        }
        vector.push(cov);
        v = cov;
        i += 1;
    }

    loop {
        if i > timesteps { break; }
        vector.push(v);
        i += 1;
    }

    Ok(vector)
}


fn parse_raw_data(path: PathBuf, timesteps: usize) -> Result<Vec<u64>, String> {
    let file = File::open(&path).unwrap();

    let mut hmap: HashMap<usize, u64> = HashMap::new();

    for line_result in BufReader::new(file).lines() {
        let line = line_result.unwrap();
        let splitted: Vec<_> = line.split(" ").collect();
        if splitted.len() < 2 {
            return Err(format!("Line in {} contains less than 2 items", path.display()));
        }
        let t0: usize = splitted.first().unwrap().parse().unwrap();
        let t: usize = t0 / 1000 / 60;
        let cov: u64 = splitted[1].parse().unwrap();

        if hmap.contains_key(&t) {
            if let Some(value) = hmap.get_mut(&t) {
                *value = cov;
            }
        } else {
            hmap.insert(t, cov);
        }
    }

    let mut vector: Vec<u64> = Vec::with_capacity(timesteps + 1);
    let mut v = 0u64;
    for i in 0..timesteps+1 {
        match hmap.get(&i) {
            Some(x) => {
                vector.push(*x);
                v = *x;
            },
            None => vector.push(v)
        }
    }

    Ok(vector)
}


fn main() {
    let mut opts = Options::new();
    opts.optflag("h", "help", "Print this help");
    opts.optopt("g", "glob", "Glob-style pattern",
        "./work/stored_work/objdump-Ht0-8h-afh-0*/coverage.log");
    opts.optopt("t", "timesteps", "Number of timesteps in runs", "480");
    opts.optflag("m", "machine", "Machine readable");
    opts.optflag("r", "raw", "Parse raw data from drivers");

    let args: Vec<_> = env::args().collect();
    let matches = opts.parse(&args[1..]).map_err(|f| f.to_string()).unwrap();

    if matches.opt_present("h") || !matches.opt_present("g") || !matches.opt_present("t") {
        println!("{}", opts.usage(&format!("Usage: {} [options]", args[0])));
        return;
    }

    let glob_pattern = matches.opt_str("g").unwrap();
    let timesteps: usize = matches.opt_str("t").unwrap().parse().unwrap();
    let machine_readable = matches.opt_present("m");
    let raw_data = matches.opt_present("r");

    let mut vectors: Vec<Vec<u64>> = Vec::new();

    for entry in glob(&glob_pattern).unwrap() {
        let vector = (if raw_data {
            parse_raw_data(entry.unwrap(), timesteps)
        } else {
            parse_master_data(entry.unwrap(), timesteps)
        }).map_err(|e| {
            eprintln!("{}", e);
            exit(1);
        }).unwrap();

        vectors.push(vector);
    }

    let n_vectors = vectors.len();
    const Z: f64 = 1.96;        // 95% C.I.
    let nv = n_vectors as f64;
    let nvsqrt = nv.sqrt();
    let mut values = Vec::with_capacity(n_vectors);
    let mut means: Vec<f64> = Vec::with_capacity(timesteps + 1);
    let mut stdes: Vec<f64> = Vec::with_capacity(timesteps + 1);
    for i in 0..timesteps+1 {
        for vector in vectors.iter() {
            values.push(vector[i]);
        }

        let mean_i = values.iter().sum::<u64>() as f64 / nv;
        means.push(mean_i);

        let var = values.iter().map(|vi| (*vi as f64 - mean_i).powi(2)).sum::<f64>() / (nv - 1f64);
        stdes.push(Z * (var.sqrt() / nvsqrt));

        if machine_readable {
            println!("{} {:.4} {:.4} {:.4}", i, mean_i, mean_i - stdes[i], mean_i + stdes[i]);
        } else {
            println!("{:8} {:>14.4} \u{00B1} {:<.4}", i, mean_i, stdes[i]);
        }

        values.clear();
    }

    exit(0);
}
