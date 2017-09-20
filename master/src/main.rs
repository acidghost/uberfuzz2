extern crate zmq;
extern crate ctrlc;
extern crate nix;

use std::convert::Into;
use std::collections::HashMap;
use std::env;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;


const WORK_PATH: &'static str = "./work";
const DEFAULT_SECTION: &'static str = ".text";
const DEFAULT_BB_SCRIPT: &'static str = "./r2.sh -b";
const INTERESTING_PORT: u32 = 5555;
const USE_PORT: u32 = INTERESTING_PORT + 1;
const METRIC_PORT_START: u32 = USE_PORT + 1;
const DRIVER_EXE: &'static str = "./driver/driver";


#[derive(Debug)]
enum FuzzerType {
    AFL,
    Honggfuzz,
    VUzzer
}

impl FromStr for FuzzerType {
    type Err = ();
    fn from_str(s: &str) -> Result<FuzzerType, ()> {
        match s {
            "afl" => Ok(FuzzerType::AFL),
            "hongg" => Ok(FuzzerType::Honggfuzz),
            "vu" => Ok(FuzzerType::VUzzer),
            _ => Err(())
        }
    }
}


#[derive(Debug)]
struct Driver {
    fuzzer_id: String,
    fuzzer_type: FuzzerType,
    section_name: String,
    fuzzer_cmd_filename: String,
    basic_block_script: String,
    fuzzer_corpus_path: String,
    interesting_port: u32,
    use_port: u32,
    metric_port: u32,
    data_path: String,
    sut: Vec<String>
}


impl Driver {
    fn new<OS, OU>(fuzzer_id: String, fuzzer_type: FuzzerType, sut: Vec<String>, metric_port: u32,
                   interesting_port: OU, use_port: OU, work_path: OS, section_name: OS,
                   basic_block_script: OS) -> Driver
                   where OS: Into<Option<String>>,
                         OU: Into<Option<u32>> {

        let work_path = work_path.into().unwrap_or(WORK_PATH.to_string());
        let corpus_path = match fuzzer_type {
            FuzzerType::AFL => "out/queue",
            FuzzerType::Honggfuzz => "in",
            FuzzerType::VUzzer => "out"
        };

        Driver {
            fuzzer_id: fuzzer_id.clone(),
            fuzzer_type: fuzzer_type,
            section_name: section_name.into().unwrap_or(DEFAULT_SECTION.to_string()),
            fuzzer_cmd_filename: format!("{}/{}.conf", work_path, fuzzer_id),
            basic_block_script: basic_block_script.into().unwrap_or(DEFAULT_BB_SCRIPT.to_string()),
            fuzzer_corpus_path: format!("{}/{}/{}", work_path, fuzzer_id, corpus_path),
            interesting_port: interesting_port.into().unwrap_or(INTERESTING_PORT),
            use_port: use_port.into().unwrap_or(USE_PORT),
            metric_port: metric_port,
            data_path: format!("{}/{}/driver", work_path, fuzzer_id),
            sut: sut
        }
    }

    fn spawn(&self) -> Child {
        let ports = format!("{},{},{}", self.interesting_port, self.use_port, self.metric_port);
        Command::new(DRIVER_EXE)
            .args(&["-i", &self.fuzzer_id])
            .args(&["-s", &self.section_name])
            .args(&["-f", &self.fuzzer_cmd_filename])
            .args(&["-b", &self.basic_block_script])
            .args(&["-c", &self.fuzzer_corpus_path])
            .args(&["-p", &ports])
            .args(&["-d", &self.data_path])
            .arg("--").args(&self.sut)
            .stdout(Stdio::null())
            .spawn()
            .expect(&format!("failed to spawn driver {}", self.fuzzer_id))
    }
}


struct Master {
    sut: Vec<String>,
    drivers: HashMap<String, Driver>,
    processes: HashMap<String, Child>
}


impl Master {
    fn from_args<'a>() -> Result<Master, &'a str> {
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

    fn start(&mut self) {
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


fn main() {
    match Master::from_args() {
        Ok(mut master) => master.start(),
        Err(e) => println!("{}", e)
    }
}
