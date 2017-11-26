use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::prelude::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::process::Child;
use std::thread;
use std::time;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use ctrlc;
use zmq;

use getopts::Options;

use time::{Duration, PreciseTime};

use rand::{Rng, thread_rng};

use inotify::{WatchMask, Inotify, WatchDescriptor};

use driver::{Driver, FuzzerType};
use messages::{InterestingInput, ReqMetric, RepMetric};
use common::{LOG_LINE_SEPARATOR, WORK_PATH};


pub const INTERESTING_PORT: u32 = 1337;
pub const USE_PORT: u32 = INTERESTING_PORT + 1;
pub const METRIC_PORT_START: u32 = USE_PORT + 1;
const BIND_ADDR: &'static str = "tcp://*";
const CONN_ADDR: &'static str = "tcp://localhost";


enum WinningStrategy {
    SingleWinner(bool),
    MultipleWinners(f64, bool)
}


struct InterestingWithTime {
    input_message: InterestingInput,
    elapsed_time: Duration
}

impl ToString for InterestingWithTime {
    fn to_string(&self) -> String {
        format!("{}{sep}{}{sep}{}{sep}{}", self.elapsed_time.num_milliseconds(),
            self.input_message.fuzzer_id, self.input_message.input_path,
            self.input_message.coverage_path, sep=LOG_LINE_SEPARATOR)
    }
}


struct WatchDescriptorData {
    fuzzer_id: String,
    modified: usize,
    ready: bool
}


pub struct Master {
    sut: Vec<String>,
    winning_strategy: WinningStrategy,
    drivers: HashMap<String, Driver>,
    processes: HashMap<String, Child>,
    interesting_pull: Option<zmq::Socket>,
    use_pub: Option<zmq::Socket>,
    metric_reqs: HashMap<String, zmq::Socket>,
    start_time: Option<PreciseTime>,
    work_path: String,
    interesting_log: Vec<InterestingWithTime>,
    interesting_log_file: Option<File>,
    winning_log_file: Option<File>
}


type BestInterestingMap = HashMap<String, Vec<(InterestingInput, RepMetric)>>;


impl Master {
    fn usage(program: &str, opts: Options) -> String {
        let brief = format!("usage: {} [options] -- target [args]", program);
        opts.usage(&brief)
    }

    pub fn from_args() -> Result<Master, String> {
        let args: Vec<String> = env::args().collect();
        let program = args[0].clone();

        let mut opts = Options::new();
        opts.optflag("h", "help", "Print this help");
        opts.optmulti("f", "fuzzer", "Fuzzer id (from id.type.conf in work directory)", "aflfast");
        opts.optflag("H", "high", "High or low winning strategy");
        opts.optopt("t", "winning-threshold", "Winning strategy threshold", "0.42");
        opts.optflag("s", "stdin", "Target reads from standard input");

        let matches = opts.parse(&args[1..]).map_err(|f| f.to_string())?;

        if matches.opt_present("h") || matches.free.is_empty() || matches.opt_count("f") < 2 {
            return Err(Master::usage(&program, opts));
        }

        // collect .conf files from WORK_PATH
        let work_readdir = fs::read_dir(WORK_PATH).map_err(|e| {
            format!("failed to read directory {}: {}", WORK_PATH, e)
        })?;

        let mut conf_files = vec![];
        for entry in work_readdir {
            let path = entry.map_err(|e| e.to_string())?.path();

            let valid_file = {
                let ext_opt = path.extension();
                path.is_file() && ext_opt.is_some() && ext_opt.unwrap() == "conf"
            };

            if valid_file {
                conf_files.push(path);
            }
        }

        debug!("found conf files: {:?}", conf_files);

        let mut drivers_map = HashMap::new();
        let mut metric_port = METRIC_PORT_START;
        for fuzzer_id in matches.opt_strs("f") {
            // find conf file starting with this fuzzer id
            let conf_path_opt = conf_files.iter().find(|p| {
                p.to_str().unwrap().contains(&fuzzer_id)
            });

            if conf_path_opt.is_none() {
                let e = format!("a config file for {} was not found in {}", fuzzer_id, WORK_PATH);
                return Err(e);
            }

            let conf_path = conf_path_opt.unwrap();
            // parse fuzzer type from conf filename
            let conf_filename = conf_path.file_name().unwrap().to_string_lossy();
            let conf_filename_split: Vec<_> = conf_filename.split(".").collect();
            if conf_filename_split.len() < 3 {
                return Err(format!("invalid conf filename {}", conf_path.display()));
            }

            let fuzzer_type: FuzzerType = conf_filename_split[1].parse().map_err(|e| {
                format!("failed to parse {}: {}", conf_filename_split[1], e)
            })?;

            let wp = WORK_PATH.to_string();

            // set sut input filename (if used)
            let sut_input_file = if matches.opt_present("s") { None }
                else { Some(format!("{}/.{}.input", wp, fuzzer_id)) };

            // set input filename (if any) in sut arguments, replacing any '@@' occurrence
            let sut = matches.free.iter().map(|s| {
                if s == "@@" { sut_input_file.clone().unwrap_or(s.to_string()) }
                else { s.to_string() }
            }).collect();

            drivers_map.insert(fuzzer_id.clone(),
                Driver::with_defaults(fuzzer_id, fuzzer_type, sut, sut_input_file, metric_port, wp));

            metric_port += 1;
        }

        let winning_strategy = match matches.opt_str("t") {
            Some(threshold_str) => {
                let threshold = threshold_str.parse().map_err(|e| {
                    format!("unable to parse {} as threshold: {}", threshold_str, e)
                })?;
                WinningStrategy::MultipleWinners(threshold, matches.opt_present("H"))
            },
            None => WinningStrategy::SingleWinner(matches.opt_present("H"))
        };

        let m = Master {
            sut: matches.free.clone(),
            winning_strategy: winning_strategy,
            drivers: drivers_map,
            processes: HashMap::new(),
            interesting_pull: None,
            use_pub: None,
            metric_reqs: HashMap::new(),
            start_time: None,
            work_path: WORK_PATH.to_string(),
            interesting_log: vec![],
            interesting_log_file: None,
            winning_log_file: None
        };

        Ok(m)
    }

    fn stop(&mut self) {
        for process in self.processes.values_mut() {
            match process.try_wait() {
                Ok(Some(_)) => (),
                Ok(None) => process.kill().expect("failed to kill driver"),
                Err(e) => panic!(e)
            }
        }
    }

    pub fn start(&mut self) {
        info!("starting master (SUT {})", self.sut.first().unwrap());

        let context = zmq::Context::new();

        {   // bind to interesting_port in PULL (pull interesting inputs)
            let socket = context.socket(zmq::PULL).expect("failed to create interesting socket");
            let address = &format!("{}:{}", BIND_ADDR, INTERESTING_PORT);
            socket.bind(address).expect(&format!("failed to bind interesting socket to {}", address));
            info!("bind 'interesting' socket {}", address);
            self.interesting_pull = Some(socket);
        }

        {   // bind to use_port in PUB (publish input to use)
            let socket = context.socket(zmq::PUB).expect("failed to create use socket");
            let address = &format!("{}:{}", BIND_ADDR, USE_PORT);
            socket.bind(address).expect(&format!("failed to bind use socket to {}", address));
            info!("bind 'use' socket {}", address);
            self.use_pub = Some(socket);
        }

        // open inputs log file
        let interesting_log_filename = format!("{}/inputs.log", self.work_path);
        match File::create(&interesting_log_filename) {
            Ok(file) => self.interesting_log_file = Some(file),
            Err(error) => {
                error!("failed to open {}: {}", interesting_log_filename, error);
                return;
            }
        }

        // open winning log file
        let winning_log_filename = format!("{}/winning.log", self.work_path);
        match File::create(&winning_log_filename) {
            Ok(file) => self.winning_log_file = Some(file),
            Err(error) => {
                error!("failed to open {}: {}", winning_log_filename, error);
                return;
            }
        }

        self.start_time = Some(PreciseTime::now());

        // spawn drivers and init inotify watchers
        let mut inotify = match Inotify::init() {
            Ok(x) => x,
            Err(e) => {
                error!("failed to init inotify: {}", e);
                return;
            }
        };
        let mut watch_descriptors: HashMap<WatchDescriptor, WatchDescriptorData> = HashMap::new();
        let mut inotify_buffer = [0u8; 4096];
        for (fuzzer_id, driver) in &self.drivers {
            self.processes.insert(fuzzer_id.clone(), driver.spawn());
            info!("started {}", fuzzer_id);

            if driver.is_vuzzer() {
                let path_to_watch = format!("{}/{}", WORK_PATH, fuzzer_id);
                let wd = match inotify.add_watch(path_to_watch, WatchMask::MODIFY) {
                    Ok(wd) => wd,
                    Err(e) => {
                        error!("failed to add inotify watcher for {}: {}", fuzzer_id, e);
                        return;
                    }
                };
                let wd_data = WatchDescriptorData {
                    fuzzer_id: fuzzer_id.clone(),
                    modified: 0,
                    ready: false
                };
                watch_descriptors.insert(wd, wd_data);
            }
        }

        // setup ctrlc handler
        let interrupted = Arc::new(AtomicBool::new(false));
        {
            let interrupted_clone = Arc::clone(&interrupted);
            let pids = self.processes.values_mut().map(|c| c.id()).collect::<Vec<u32>>().clone();
            ctrlc::set_handler(move || {
                interrupted_clone.store(true, Ordering::Relaxed);
                for pid in &pids {
                    kill(Pid::from_raw(*pid as i32), Signal::SIGKILL)
                        .expect("failed to kill driver");
                }
            }).expect("failed to set interrupt handler");
        }

        // connect to metric_port in REQ for each driver (requests metric to driver)
        for (fuzzer_id, driver) in &self.drivers {
            let socket = context.socket(zmq::REQ).expect("failed to create metric socket");
            let address = &format!("{}:{}", CONN_ADDR, driver.get_metric_port());
            socket.connect(address).expect(&format!("failed to connecto to metric socket {}", address));
            self.metric_reqs.insert(fuzzer_id.clone(), socket);
        }

        // this table contains the best interesting input for slower fuzzers that need throttling
        let mut best_interesting: BestInterestingMap = HashMap::new();
        for wdata in watch_descriptors.values() {
            best_interesting.insert(wdata.fuzzer_id.clone(), vec![]);
        }

        let high_strategy = self.get_high_strategy();
        let mut pulled_interesting = false;
        let mut pending_newline = false;
        'outer: while !interrupted.load(Ordering::Relaxed) {
            // check drivers liveness
            for (fuzzer_id, process) in &mut self.processes {
                match process.try_wait() {
                    Ok(Some(status)) => {
                        let status_str = if status.success() {"normally"} else {"with error"};
                        warn!("{} exited {}", fuzzer_id, status_str);
                        break 'outer;
                    },
                    Ok(None) => (),
                    Err(e) => {
                        error!("{}", e);
                        break 'outer;
                    }
                }
            }

            // check inotify events
            match inotify.read_events(&mut inotify_buffer) {
                Ok(events) => {
                    for event in events {
                        if event.name.is_some() && event.name.unwrap() == "stats.log" {
                            let wd_data = watch_descriptors.get_mut(&event.wd).unwrap();
                            wd_data.modified += 1;
                            if wd_data.modified > 1 {
                                wd_data.ready = true;
                            }
                            debug!("inotify event on {} (modified {})",
                                wd_data.fuzzer_id, wd_data.modified);
                        }
                    }
                },
                Err(e) => {
                    error!("failed to read inotify events: {}", e);
                    break;
                }
            };

            // try pulling new interesting input and process any
            match self.pull_interesting() {
                Ok(Some(interesting)) => {
                    if pending_newline {
                        print!("\r");
                        pending_newline = false;
                    }
                    pulled_interesting = true;
                    if let Err(e) = self.log_interesting(&interesting) {
                        error!("failed logging: {}", e);
                        break;
                    }

                    let process_res = self.process_interesting(interesting,
                        watch_descriptors.values(), &mut best_interesting);
                    if let Err(e) = process_res {
                        error!("failed to process interesting: {}", e);
                        break;
                    }
                },
                Ok(None) => {
                    if !pulled_interesting && pending_newline {
                        print!("\r");
                    }
                    let t = self.start_time.unwrap().to(PreciseTime::now());
                    print!("{:02}:{:02}:{:02}",
                        t.num_hours(), t.num_minutes() % 60, t.num_seconds() % 60);
                    pulled_interesting = false;
                    pending_newline = true;
                },
                Err(e) => {
                    error!("failed to pull interesting: {}", e);
                    break;
                }
            }

            // check if watched fuzzers are ready and send the best of collected interesting inputs
            for wdata in watch_descriptors.values_mut() {
                if !wdata.ready { continue; }

                let best_vec = best_interesting.get_mut(&wdata.fuzzer_id).unwrap();
                best_vec.sort_unstable_by(|t1, t2| {
                    let m1 = &t1.1.metric;
                    let m2 = &t2.1.metric;
                    m1.partial_cmp(m2).unwrap_or(::std::cmp::Ordering::Equal)
                });

                let best = (if high_strategy { best_vec.last() } else { best_vec.first() })
                    .map(|t| t.to_owned());

                if let Some((ref b, ref m)) = best {
                    let assign_res = self.assign_input(b, &[wdata.fuzzer_id.clone()]);
                    if let Err(e) = assign_res {
                        error!("failed to assign to {}: {}", wdata.fuzzer_id, e);
                        break 'outer;
                    }
                    if pending_newline {
                        print!("\r");
                    }
                    let t = self.start_time.unwrap().to(PreciseTime::now());
                    println!("{:02}:{:02}:{:02} - {} - {} {}",
                        t.num_hours(), t.num_minutes() % 60, t.num_seconds() % 60,
                        b.fuzzer_id, wdata.fuzzer_id, m.metric);
                    pending_newline = false;
                    wdata.ready = false;
                    best_vec.clear();

                    if let Some(ref mut file) = self.winning_log_file {
                        let line = format!("{}{sep}{}{sep}{}\n",
                            t.num_milliseconds(), b.fuzzer_id, wdata.fuzzer_id,
                            sep=LOG_LINE_SEPARATOR);
                        if let Err(e) = file.write_all(line.as_bytes()) {
                            error!("failed writing to {}: {}", winning_log_filename, e);
                            break 'outer;
                        }
                    }
                }
            }

            thread::sleep(time::Duration::from_millis(10));
        }

        if !interrupted.load(Ordering::Relaxed) {
            self.stop();
        }
    }

    fn pull_interesting(&self) -> Result<Option<InterestingInput>, String> {
        match self.interesting_pull.as_ref().unwrap().recv_bytes(zmq::DONTWAIT) {
            Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).parse()?)),
            Err(zmq::Error::EAGAIN) => Ok(None),
            Err(error) => Err(error.to_string())
        }
    }

    fn log_interesting(&mut self, interesting_input: &InterestingInput)
        -> Result<(), String>
    {
        let interesting_with_time = InterestingWithTime {
            input_message: interesting_input.clone(),
            elapsed_time: self.start_time.unwrap().to(PreciseTime::now())
        };

        if let Some(ref mut file) = self.interesting_log_file {
            let line = interesting_with_time.to_string() + "\n";
            file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        }

        self.interesting_log.push(interesting_with_time);

        Ok(())
    }

    fn get_high_strategy(&self) -> bool {
        match self.winning_strategy {
            WinningStrategy::SingleWinner(highest) => highest,
            WinningStrategy::MultipleWinners(_, higher) => higher
        }
    }

    fn process_interesting<'a, W>(&mut self, interesting_input: InterestingInput, watch_data: W,
        best_interesting: &mut BestInterestingMap)
        -> Result<(), String>
        where W: Iterator<Item=&'a WatchDescriptorData>
    {
        let start_processing_duration = self.start_time.unwrap().to(PreciseTime::now());

        let metrics = self.evaluate_interesting(&interesting_input)?;

        // update best_interesting table
        for (fuzzer_id, metric_rep) in &metrics {
            if metric_rep.metric == 0.0 { continue; }
            if let Some(best_vec) = best_interesting.get_mut(fuzzer_id) {
                best_vec.push((interesting_input.clone(), metric_rep.clone()));
            }
        }

        // if from VUzzer, broadcast it if metric is not zero
        let winning_drivers = if self.drivers.get(&interesting_input.fuzzer_id).unwrap().is_vuzzer() {
            self.drivers.keys().filter_map(|f| {
                // if the sender is not f, then check metric value (metric must exist for f)
                if *f == interesting_input.fuzzer_id || metrics.get(f).unwrap().metric == 0.0 { None }
                else { Some(f.to_owned()) }
            }).collect()
        } else {
            let mut metrics_c = metrics.clone();
            for wdata in watch_data {
                metrics_c.remove(&wdata.fuzzer_id);
            }
            self.metric_winners(&metrics_c)?
        };

        if !winning_drivers.is_empty() {
            self.assign_input(&interesting_input, &winning_drivers)?;

            // log competition
            if let Some(ref mut file) = self.winning_log_file {
                let mut winning_drivers_sort = winning_drivers.clone();
                winning_drivers_sort.sort();
                let line = format!("{}{sep}{}{sep}{}\n",
                    start_processing_duration.num_milliseconds(), interesting_input.fuzzer_id,
                    winning_drivers_sort.join("_"), sep=LOG_LINE_SEPARATOR);
                file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
            }
        }

        println!("{:02}:{:02}:{:02} - {} - {} - {}",
            start_processing_duration.num_hours(),
            start_processing_duration.num_minutes() % 60,
            start_processing_duration.num_seconds() % 60,
            interesting_input.fuzzer_id,
            metrics.iter().map(|t| format!("{} {}", t.0, t.1.metric))
             .collect::<Vec<_>>().join(" / "),
            if winning_drivers.len() > 0 { winning_drivers.join(" ") }
            else { "none".to_string() });

        Ok(())
    }

    fn evaluate_interesting(&self, interesting_input: &InterestingInput)
        -> Result<HashMap<String, RepMetric>, String>
    {
        let mut metrics = HashMap::new();
        let request = ReqMetric { coverage_path: interesting_input.coverage_path.clone() };
        for (fuzzer_id, metric_socket) in &self.metric_reqs {
            if *fuzzer_id == interesting_input.fuzzer_id {
                continue;
            }

            metric_socket.send_str(&request.to_string(), 0).map_err(|e| {
                format!("error sending metric req to {}: {}", fuzzer_id, e)
            })?;

            let rep_bytes = metric_socket.recv_bytes(0).map_err(|e| {
                format!("error receiving metric rep from {}: {}", fuzzer_id, e)
            })?;

            let rep = String::from_utf8_lossy(&rep_bytes).parse().map_err(|e| {
                format!("error parsing metric rep from {}: {}", fuzzer_id, e)
            })?;

            metrics.insert(fuzzer_id.clone(), rep);
        }

        Ok(metrics)
    }

    fn metric_winners(&self, metrics: &HashMap<String, RepMetric>)
        -> Result<Vec<String>, String>
    {
        let winning_drivers = match self.winning_strategy {
            WinningStrategy::SingleWinner(highest) => {
                if let Some(w) = Master::metric_single_winner(&metrics, highest)? {
                    vec![w]
                } else {
                    vec![]
                }
            },
            WinningStrategy::MultipleWinners(threshold, higher) => {
                Master::metric_multiple_winners(&metrics, threshold, higher)?
            }
        };

        Ok(winning_drivers)
    }

    fn metric_single_winner(metrics: &HashMap<String, RepMetric>, highest: bool)
        -> Result<Option<String>, String>
    {
        if metrics.iter().all(|tpl| tpl.1.metric == 0.0) {
            return Ok(None);
        }

        // shuffling is done so that in cases where the metrics are all equal a different one gets
        // picked each time
        let mut metrics_vec: Vec<_> = metrics.iter().collect();
        thread_rng().shuffle(metrics_vec.as_mut_slice());

        let mut iter = metrics_vec.iter();
        let (mut winning_key, mut winning_val) = *iter.next()
            .ok_or("metrics hashmap is empty".to_string())?;

        for tpl in iter {
            let (k, v) = *tpl;
            if (highest && v.metric > winning_val.metric) ||
                (!highest && v.metric < winning_val.metric)
            {
                winning_val = v;
                winning_key = k;
            }
        }

        Ok(Some(winning_key.clone()))
    }

    fn metric_multiple_winners(metrics: &HashMap<String, RepMetric>, threshold: f64, higher: bool)
        -> Result<Vec<String>, String>
    {
        let mut winners = vec![];

        for (k, v) in metrics {
            if (higher && v.metric > threshold) || (!higher && v.metric < threshold) {
                winners.push(k.clone());
            }
        }

        Ok(winners)

    }

    fn assign_input(&self, interesting_input: &InterestingInput, fuzzer_ids: &[String])
        -> Result<(), String>
    {
        let input = interesting_input.use_for(fuzzer_ids);
        self.use_pub.as_ref().unwrap().send_str(&input.to_string(), 0).map_err(|e| {
            format!("error publishing input to use: {}", e)
        })
    }
}
