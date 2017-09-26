use std::collections::HashMap;
use std::env;
use std::fs::File;
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

use driver::{Driver, FuzzerType};
use messages::{InterestingInput, ReqMetric, RepMetric};


const WORK_PATH: &'static str = "./work";
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
        format!("{},{},{},{}", self.elapsed_time.num_milliseconds(), self.input_message.fuzzer_id,
            self.input_message.input_path, self.input_message.coverage_path)
    }
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
    interesting_log_file: Option<File>
}


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
        opts.optmulti("f", "fuzzer", "Pair of fuzzer id and fuzzer type", "aflfast,afl");
        opts.optflag("w", "winning-high", "High or low winning strategy");
        opts.optopt("t", "winning-threshold", "Winning strategy threshold", "0.42");

        let matches = opts.parse(&args[1..]).map_err(|f| f.to_string())?;
        let sut = &matches.free;

        if matches.opt_present("h") || sut.is_empty() || matches.opt_count("f") < 2 {
            return Err(Master::usage(&program, opts));
        }

        let mut drivers_map = HashMap::new();
        let mut metric_port = METRIC_PORT_START;
        for fuzzer_str in matches.opt_strs("f") {
            let mut splitted = fuzzer_str.split(",");
            let fuzzer_id = splitted.next().expect("only one argument for fuzzer").to_string();
            let fuzzer_type = splitted.next().expect("fuzzer type missing")
                .parse::<FuzzerType>().expect("wrong fuzzer type");

            let wp = WORK_PATH.to_string();
            drivers_map.insert(fuzzer_id.clone(),
                Driver::with_defaults(fuzzer_id, fuzzer_type, sut.clone(), metric_port, wp));

            metric_port += 1;
        }

        let winning_strategy = match matches.opt_str("t") {
            Some(threshold_str) => {
                let threshold = threshold_str.parse().map_err(|e| {
                    format!("unable to parse {} as threshold: {}", threshold_str, e)
                })?;
                WinningStrategy::MultipleWinners(threshold, matches.opt_present("w"))
            },
            None => WinningStrategy::SingleWinner(matches.opt_present("w"))
        };

        let m = Master {
            sut: sut.clone(),
            winning_strategy: winning_strategy,
            drivers: drivers_map,
            processes: HashMap::new(),
            interesting_pull: None,
            use_pub: None,
            metric_reqs: HashMap::new(),
            start_time: None,
            work_path: WORK_PATH.to_string(),
            interesting_log: vec![],
            interesting_log_file: None
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

        // open log file
        let interesting_log_filename = format!("{}/inputs.log", self.work_path);
        match File::create(&interesting_log_filename) {
            Ok(file) => self.interesting_log_file = Some(file),
            Err(error) => {
                error!("failed to open {}: {}", interesting_log_filename, error);
                return;
            }
        }

        self.start_time = Some(PreciseTime::now());

        // spawn drivers
        for (fuzzer_id, driver) in &self.drivers {
            self.processes.insert(fuzzer_id.clone(), driver.spawn());
            info!("started {}", fuzzer_id);
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

            // try pulling new interesting input and process any
            match self.pull_interesting() {
                Ok(Some(interesting)) => {
                    if let Err(e) = self.log_interesting(&interesting) {
                        error!("failed logging: {}", e);
                        break;
                    }

                    if let Err(e) = self.process_interesting(interesting) {
                        error!("failed to process interesting: {}", e);
                        break;
                    }
                },
                Ok(None) => (),
                Err(e) => {
                    error!("failed to pull interesting: {}", e);
                    break;
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

    fn process_interesting(&self, interesting_input: InterestingInput)
        -> Result<(), String>
    {
        info!("new input from {}", interesting_input.fuzzer_id);

        let metrics = self.evaluate_interesting(&interesting_input)?;
        info!("metrics:{}", metrics.iter().map(|t| format!("({} {})", t.0, t.1.metric))
            .collect::<Vec<_>>().join(" "));

        let winning_drivers = self.metric_winners(&metrics)?;

        if !winning_drivers.is_empty() {
            let winning_drivers_str = winning_drivers.join(" - ");
            info!("winning drivers: {}", winning_drivers_str);
            self.assign_input(&interesting_input, &winning_drivers)?;
            info!("input sent to {}", winning_drivers_str);
        } else {
            debug!("no winning driver");
        }

        Ok(())
    }

    fn evaluate_interesting(&self, interesting_input: &InterestingInput)
        -> Result<HashMap<&str, RepMetric>, String>
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

            metrics.insert(fuzzer_id.as_str(), rep);
        }

        Ok(metrics)
    }

    fn metric_winners<'a>(&self, metrics: &HashMap<&'a str, RepMetric>)
        -> Result<Vec<&'a str>, String>
    {
        match self.winning_strategy {
            WinningStrategy::SingleWinner(highest) => {
                let winning_driver = Master::metric_single_winner(&metrics, highest)?;
                Ok(vec![winning_driver])
            },
            WinningStrategy::MultipleWinners(threshold, higher) => {
                let winning_drivers = Master::metric_multiple_winners(&metrics, threshold, higher)?;
                Ok(winning_drivers)
            }
        }
    }

    fn metric_single_winner<'a>(metrics: &HashMap<&'a str, RepMetric>, highest: bool)
        -> Result<&'a str, String>
    {
        let mut iter = metrics.iter();
        let (mut winning_key, mut winning_val) = match iter.next() {
            Some(x) => x,
            None => return Err("metrics hashmap is empty".to_string())
        };

        for (k, v) in iter {
            if (highest && v.metric > winning_val.metric) ||
                (!highest && v.metric < winning_val.metric)
            {
                winning_val = v;
                winning_key = k;
            }
        }

        Ok(winning_key)
    }

    fn metric_multiple_winners<'a>(metrics: &HashMap<&'a str, RepMetric>, threshold: f64, higher: bool)
        -> Result<Vec<&'a str>, String>
    {
        let mut winners = vec![];

        for (k, v) in metrics {
            if (higher && v.metric > threshold) || (!higher && v.metric < threshold) {
                winners.push(*k);
            }
        }

        Ok(winners)

    }

    fn assign_input(&self, interesting_input: &InterestingInput, fuzzer_ids: &[&str])
        -> Result<(), String>
    {
        let input = interesting_input.use_for(fuzzer_ids);
        self.use_pub.as_ref().unwrap().send_str(&input.to_string(), 0).map_err(|e| {
            format!("error publishing input to use: {}", e)
        })
    }
}
