// messages exchanged with drivers

#[derive(Debug)]
pub struct InterestingInput {
    pub fuzzer_id: String,
    pub input_path: String,
    pub coverage_path: String
}


#[derive(Debug)]
pub struct UseInput {
    pub fuzzer_id: String,
    pub input_path: String
}
