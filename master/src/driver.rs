use std::convert::Into;
use std::str::FromStr;
use std::process::{Child, Command, Stdio};

use master;


const WORK_PATH: &'static str = "./work";
const DEFAULT_SECTION: &'static str = ".text";
const DEFAULT_BB_SCRIPT: &'static str = "./r2.sh -b";
const DRIVER_EXE: &'static str = "./driver/driver";


#[derive(Debug)]
pub enum FuzzerType {
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
pub struct Driver {
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
    pub fn new<OS, OU>(fuzzer_id: String, fuzzer_type: FuzzerType, sut: Vec<String>, metric_port: u32,
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
            interesting_port: interesting_port.into().unwrap_or(master::INTERESTING_PORT),
            use_port: use_port.into().unwrap_or(master::USE_PORT),
            metric_port: metric_port,
            data_path: format!("{}/{}/driver", work_path, fuzzer_id),
            sut: sut
        }
    }

    pub fn spawn(&self) -> Child {
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
