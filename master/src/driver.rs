use std::convert::{From, Into};
use std::fs::File;
use std::str::FromStr;
use std::process::{Child, Command, Stdio};

use master;


const DRIVER_EXE: &'static str = "./driver/driver";


#[derive(Debug, Clone, Copy, PartialEq)]
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
            &FuzzerType::VUzzer => "special"
        }
    }
}

impl FromStr for FuzzerType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "afl" => Ok(FuzzerType::AFL),
            "hongg" => Ok(FuzzerType::Honggfuzz),
            "vu" => Ok(FuzzerType::VUzzer),
            _ => Err(format!("unable to parse {}", s))
        }
    }
}

impl ToString for FuzzerType {
    fn to_string(&self) -> String {
        match self {
            &FuzzerType::AFL => "afl",
            &FuzzerType::Honggfuzz => "hongg",
            &FuzzerType::VUzzer => "vu"
        }.to_string()
    }
}


#[derive(Debug)]
pub struct Driver {
    fuzzer_id: String,
    fuzzer_type: FuzzerType,
    section_name: Option<String>,
    fuzzer_cmd_filename: String,
    basic_block_script: Option<String>,
    fuzzer_corpus_path: String,
    fuzzer_log_filename: String,
    fuzzer_log_err_filename: String,
    interesting_port: u32,
    use_port: u32,
    metric_port: u32,
    data_path: String,
    inject_path: String,
    sut: Vec<String>,
    sut_input_file: Option<String>,
    log_filename: String
}


impl Driver {
    pub fn with_defaults(fuzzer_id: String, fuzzer_type: FuzzerType, sut: Vec<String>,
                         sut_input_file: Option<String>, metric_port: u32, work_path: String,
                         basic_block_script: Option<String>, section_name: Option<String>)
                         -> Driver
    {
        Driver::new(fuzzer_id, fuzzer_type, sut, sut_input_file, metric_port, work_path,
            basic_block_script, section_name, None, None)
    }

    pub fn new<OS, OU>(fuzzer_id: String, fuzzer_type: FuzzerType, sut: Vec<String>,
                       sut_input_file: Option<String>, metric_port: u32, work_path: String,
                       basic_block_script: OS, section_name: OS, interesting_port: OU, use_port: OU)
                       -> Driver
                       where OS: Into<Option<String>>,
                             OU: Into<Option<u32>>
    {
        let corpus_path = match fuzzer_type {
            FuzzerType::AFL => format!("out/{}/queue", fuzzer_id),
            FuzzerType::Honggfuzz => "in".to_string(),
            FuzzerType::VUzzer => "special".to_string()
        };

        let inject_path = fuzzer_type.get_inject_path();

        Driver {
            fuzzer_id: fuzzer_id.clone(),
            fuzzer_type: fuzzer_type,
            section_name: section_name.into(),
            fuzzer_cmd_filename: format!("{}/{}.{}.conf", work_path, fuzzer_id, fuzzer_type.to_string()),
            basic_block_script: basic_block_script.into(),
            fuzzer_corpus_path: format!("{}/{}/{}", work_path, fuzzer_id, corpus_path),
            fuzzer_log_filename: format!("{}/{}.fuzz.log", work_path, fuzzer_id),
            fuzzer_log_err_filename: format!("{}/{}.fuzz.err.log", work_path, fuzzer_id),
            interesting_port: interesting_port.into().unwrap_or(master::INTERESTING_PORT),
            use_port: use_port.into().unwrap_or(master::USE_PORT),
            metric_port: metric_port,
            data_path: format!("{}/{}/driver", work_path, fuzzer_id),
            inject_path: format!("{}/{}/{}", work_path, fuzzer_id, inject_path),
            sut: sut,
            sut_input_file: sut_input_file,
            log_filename: format!("{}/{}.log", work_path, fuzzer_id)
        }
    }

    pub fn spawn(&self) -> Child {
        let ports = format!("{},{},{}", self.interesting_port, self.use_port, self.metric_port);
        let file: File = File::create(&self.log_filename)
            .expect(&format!("failed to create {}", self.log_filename));

        let mut args = vec![
            "-i", &self.fuzzer_id,
            "-f", &self.fuzzer_cmd_filename,
            "-c", &self.fuzzer_corpus_path,
            "-l", &self.fuzzer_log_filename,
            "-L", &self.fuzzer_log_err_filename,
            "-p", &ports,
            "-d", &self.data_path,
            "-j", &self.inject_path
        ];

        if let Some(ref basic_block_script) = self.basic_block_script {
            args.extend_from_slice(&["-b", basic_block_script]);
        }

        if let Some(ref section_name) = self.section_name {
            args.extend_from_slice(&["-s", section_name]);
        }

        if let Some(ref sut_input_file) = self.sut_input_file {
            args.extend_from_slice(&["-F", sut_input_file]);
        }

        args.push("--");
        args.extend_from_slice(&self.sut.iter().map(|s| s.as_ref()).collect::<Vec<_>>());

        Command::new(DRIVER_EXE)
            .args(&args)
            .stdout(Stdio::from(file))
            // FIXME: .stderr(Stdio::from(file))
            .spawn()
            .expect(&format!("failed to spawn driver {}", self.fuzzer_id))
    }

    pub fn get_metric_port(&self) -> u32 { self.metric_port }

    pub fn is_vuzzer(&self) -> bool { self.fuzzer_type == FuzzerType::VUzzer }
}
