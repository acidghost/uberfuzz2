use std::str::FromStr;

// messages exchanged with drivers

#[derive(Debug, Clone)]
pub struct InterestingInput {
    pub fuzzer_id: String,
    pub input_path: String,
    pub coverage_path: String
}

impl InterestingInput {
    pub fn use_for(&self, fuzzer_ids: &[String]) -> UseInput {
        UseInput {
            fuzzer_ids: fuzzer_ids.iter().map(|f| f.to_string()).collect(),
            input_path: self.input_path.clone(),
            coverage_path: self.coverage_path.clone()
        }
    }
}

impl FromStr for InterestingInput {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut splitted = s.split(" ");

        let mut parse_next = |field_name| {
            splitted.next().ok_or(format!("unable to parse {} from '{}'", field_name, s))
        };

        let fuzzer_id = parse_next("fuzzer_id")?;
        let input_path = parse_next("input_path")?;
        let coverage_path = parse_next("coverage_path")?;

        let interesting_input = InterestingInput {
            fuzzer_id: fuzzer_id.to_string().clone(),
            input_path: input_path.to_string().clone(),
            coverage_path: coverage_path.to_string().clone()
        };

        Ok(interesting_input)
    }
}


#[derive(Debug)]
pub struct UseInput {
    fuzzer_ids: Vec<String>,
    input_path: String,
    coverage_path: String
}

impl ToString for UseInput {
    fn to_string(&self) -> String {
        // the 'A' is the subscription topic, by subscribing to it drivers can receive all messages
        format!("A {} {} {}", self.fuzzer_ids.join("_"), self.input_path, self.coverage_path)
    }
}


#[derive(Debug)]
pub struct ReqMetric {
    pub coverage_path: String
}

impl ToString for ReqMetric {
    fn to_string(&self) -> String { self.coverage_path.clone() }
}


#[derive(Debug, Clone)]
pub struct RepMetric {
    pub metric: f64
}

impl FromStr for RepMetric {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let metric = s.parse().map_err(|e| {
            format!("failed parsing metric {}. {}", s, e)
        })?;

        Ok(RepMetric { metric: metric })
    }
}
