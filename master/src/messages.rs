use std::str::FromStr;

// messages exchanged with drivers

#[derive(Debug)]
pub struct InterestingInput {
    pub fuzzer_id: String,
    pub input_path: String,
    pub coverage_path: String
}

impl FromStr for InterestingInput {
    type Err = ();
    fn from_str(s: &str) -> Result<InterestingInput, ()> {
        let mut splitted = s.split(" ");
        let interesting_input = InterestingInput {
            fuzzer_id: splitted.nth(0).unwrap().to_string().clone(),
            input_path: splitted.nth(0).unwrap().to_string().clone(),
            coverage_path: splitted.nth(0).unwrap().to_string().clone()
        };
        Ok(interesting_input)
    }
}

impl ToString for InterestingInput {
    fn to_string(&self) -> String {
        format!("{} {} {}", self.fuzzer_id, self.input_path, self.coverage_path)
    }
}


#[derive(Debug)]
pub struct ReqMetric {
    pub coverage_path: String
}

impl ToString for ReqMetric {
    fn to_string(&self) -> String { self.coverage_path.clone() }
}


#[derive(Debug)]
pub struct RepMetric {
    pub metric: f64
}

impl FromStr for RepMetric {
    type Err = ();
    fn from_str(s: &str) -> Result<RepMetric, ()> {
        Ok(
            RepMetric {
                metric: s.parse().unwrap()
            }
        )
    }
}
