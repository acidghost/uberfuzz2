use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::process::Child;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use ctrlc;

use driver::{Driver, FuzzerType};


pub const INTERESTING_PORT: u32 = 5555;
pub const USE_PORT: u32 = INTERESTING_PORT + 1;
pub const METRIC_PORT_START: u32 = USE_PORT + 1;


pub struct Master {
    sut: Vec<String>,
    drivers: HashMap<String, Driver>,
    processes: HashMap<String, Child>
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
            Ok(Master {
                sut: sut,
                drivers: drivers_map,
                processes: HashMap::new()
            })
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

        for (fuzzer_id, driver) in &self.drivers {
            self.processes.insert(fuzzer_id.clone(), driver.spawn());
            println!("started {}", fuzzer_id);
        }

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
        }

        if !interrupted.load(Ordering::Relaxed) {
            self.stop();
        }
    }
}
