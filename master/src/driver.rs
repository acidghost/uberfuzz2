use std::convert::{From, Into};
use std::fs::File;
use std::str::FromStr;
use std::process::{Child, Command, Stdio};

use master;


const DEFAULT_SECTION: &'static str = ".text";
const DEFAULT_BB_SCRIPT: &'static str = "./r2.sh -b";
const DRIVER_EXE: &'static str = "./driver/driver";


#[derive(Debug)]
pub enum FuzzerType {
    AFL,
    Honggfuzz,
    VUzzer
}

impl FuzzerType {
    fn get_inject_path(&self) -> &'static str {
        match self {
            &FuzzerType::AFL => "out/inject/queue",
            &FuzzerType::Honggfuzz => "out/inject",
            &FuzzerType::VUzzer => "out"
        }
    }
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
    fuzzer_log_filename: String,
    interesting_port: u32,
    use_port: u32,
    metric_port: u32,
    data_path: String,
    inject_path: String,
    sut: Vec<String>,
    log_filename: String
}


impl Driver {
    pub fn with_defaults(fuzzer_id: String, fuzzer_type: FuzzerType, sut: Vec<String>,
                         metric_port: u32, work_path: String) -> Driver
    {
        Driver::new(fuzzer_id, fuzzer_type, sut, metric_port, work_path, None, None, None, None)
    }

    pub fn new<OS, OU>(fuzzer_id: String, fuzzer_type: FuzzerType, sut: Vec<String>,
                       metric_port: u32, work_path: String, interesting_port: OU, use_port: OU,
                       section_name: OS, basic_block_script: OS) -> Driver
                       where OS: Into<Option<String>>,
                             OU: Into<Option<u32>>
    {
        let corpus_path = match fuzzer_type {
            FuzzerType::AFL => format!("out/{}/queue", fuzzer_id),
            FuzzerType::Honggfuzz => "in".to_string(),
            FuzzerType::VUzzer => "out".to_string()
        };

        let inject_path = fuzzer_type.get_inject_path();

        Driver {
            fuzzer_id: fuzzer_id.clone(),
            fuzzer_type: fuzzer_type,
            section_name: section_name.into().unwrap_or(DEFAULT_SECTION.to_string()),
            fuzzer_cmd_filename: format!("{}/{}.conf", work_path, fuzzer_id),
            basic_block_script: basic_block_script.into().unwrap_or(DEFAULT_BB_SCRIPT.to_string()),
            fuzzer_corpus_path: format!("{}/{}/{}", work_path, fuzzer_id, corpus_path),
            fuzzer_log_filename: format!("{}/{}.fuzz.log", work_path, fuzzer_id),
            interesting_port: interesting_port.into().unwrap_or(master::INTERESTING_PORT),
            use_port: use_port.into().unwrap_or(master::USE_PORT),
            metric_port: metric_port,
            data_path: format!("{}/{}/driver", work_path, fuzzer_id),
            inject_path: format!("{}/{}/{}", work_path, fuzzer_id, inject_path),
            sut: sut,
            log_filename: format!("{}/{}.log", work_path, fuzzer_id)
        }
    }

    pub fn spawn(&self) -> Child {
        let ports = format!("{},{},{}", self.interesting_port, self.use_port, self.metric_port);
        let file: File = File::create(&self.log_filename)
            .expect(&format!("failed to create {}", self.log_filename));

        Command::new(DRIVER_EXE)
            .args(&["-i", &self.fuzzer_id])
            .args(&["-s", &self.section_name])
            .args(&["-f", &self.fuzzer_cmd_filename])
            .args(&["-b", &self.basic_block_script])
            .args(&["-c", &self.fuzzer_corpus_path])
            .args(&["-l", &self.fuzzer_log_filename])
            .args(&["-p", &ports])
            .args(&["-d", &self.data_path])
            .args(&["-j", &self.inject_path])
            .arg("--").args(&self.sut)
            .stdout(Stdio::from(file))
            // FIXME: .stderr(Stdio::from(file))
            .spawn()
            .expect(&format!("failed to spawn driver {}", self.fuzzer_id))
    }

    pub fn get_metric_port(&self) -> u32 {
        self.metric_port
    }
}
