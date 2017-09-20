use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::process::Child;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use ctrlc;
use zmq;

use driver::{Driver, FuzzerType};
use messages::{InterestingInput, UseInput};


pub const INTERESTING_PORT: u32 = 1337;
pub const USE_PORT: u32 = INTERESTING_PORT + 1;
pub const METRIC_PORT_START: u32 = USE_PORT + 1;
const BIND_ADDR: &'static str = "tcp://*";
const CONN_ADDR: &'static str = "tcp://localhost";


pub struct Master {
    sut: Vec<String>,
    drivers: HashMap<String, Driver>,
    processes: HashMap<String, Child>,
    interesting_pull: Option<zmq::Socket>,
    use_pub: Option<zmq::Socket>,
    metric_reqs: HashMap<String, zmq::Socket>
}


impl Master {
    pub fn from_args<'a>() -> Result<Master, &'a str> {
        let mut sut = vec![];
        let mut do_sut = false;
        let mut metric_port = METRIC_PORT_START;
        let mut drivers = vec![];
        for arg in env::args().skip(1) {
            match arg.as_str() {
                x if do_sut => sut.push(x.to_string()),
                "--" => do_sut = true,
                x => {
                    let s = x.to_string();
                    let mut splitted = s.split(",");
                    let driver = (
                        splitted.next().expect("only one argument for fuzzer").to_string(),
                        splitted.next().expect("fuzzer type missing")
                            .parse::<FuzzerType>().expect("wrong fuzzer type"),
                        metric_port);
                    drivers.push(driver);
                    metric_port += 1;
                }
            }
        }

        if !(drivers.len() > 1 && sut.len() > 0) {
            Err("usage: master fID,fType -- sut [args]")
        } else {
            let mut drivers_map = HashMap::new();
            for driver_data in drivers {
                let (fuzzer_id, fuzzer_type, metric_port) = driver_data;
                let driver = Driver::new(fuzzer_id.clone(), fuzzer_type, sut.clone(), metric_port,
                    None, None, None, None, None);
                drivers_map.insert(fuzzer_id, driver);
            }

            let m = Master {
                sut: sut,
                drivers: drivers_map,
                processes: HashMap::new(),
                interesting_pull: None,
                use_pub: None,
                metric_reqs: HashMap::new()
            };

            Ok(m)
        }
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
        println!("starting master (SUT {})", self.sut.first().unwrap());

        let context = zmq::Context::new();

        {   // bind to interesting_port in PULL (pull interesting inputs)
            let socket = context.socket(zmq::PULL).expect("failed to create interesting socket");
            let address = &format!("{}:{}", BIND_ADDR, INTERESTING_PORT);
            socket.bind(address).expect(&format!("failed to bind interesting socket to {}", address));
            println!("bind 'interesting' socket {}", address);
            self.interesting_pull = Some(socket);
        }

        {   // bind to use_port in PUB (publish input to use)
            let socket = context.socket(zmq::PUB).expect("failed to create use socket");
            let address = &format!("{}:{}", BIND_ADDR, USE_PORT);
            socket.bind(address).expect(&format!("failed to bind use socket to {}", address));
            println!("bind 'use' socket {}", address);
            self.use_pub = Some(socket);
        }

        // spawn drivers
        for (fuzzer_id, driver) in &self.drivers {
            self.processes.insert(fuzzer_id.clone(), driver.spawn());
            println!("started {}", fuzzer_id);
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
            for (fuzzer_id, process) in &mut self.processes {
                match process.try_wait() {
                    Ok(Some(status)) => {
                        let status_str = if status.success() {"normally"} else {"with error"};
                        println!("{} exited {}", fuzzer_id, status_str);
                        break 'outer;
                    },
                    Ok(None) => (),
                    Err(e) => {
                        println!("{}", e);
                        break 'outer;
                    }
                }
            }

            if let Some(interesting_input) = self.pull_interesting() {
                println!("{:?}", interesting_input);
                // TODO: propagate interesting_input
            }
        }

        if !interrupted.load(Ordering::Relaxed) {
            self.stop();
        }
    }

    fn pull_interesting(&self) -> Option<InterestingInput> {
        match self.interesting_pull.as_ref().unwrap().recv_bytes(zmq::DONTWAIT) {
            Ok(bytes) => {
                let mut message_cow = String::from_utf8_lossy(&bytes);
                let mut splitted = message_cow.to_mut().split(" ");
                let interesting_input = InterestingInput {
                    fuzzer_id: splitted.nth(0).unwrap().to_string().clone(),
                    input_path: splitted.nth(0).unwrap().to_string().clone(),
                    coverage_path: splitted.nth(0).unwrap().to_string().clone()
                };

                Some(interesting_input)
            },
            Err(zmq::Error::EAGAIN) => None,
            Err(error) => panic!("pull_interesting error {:?}", error)
        }
    }
}
