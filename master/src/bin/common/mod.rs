use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};


pub const SEPARATOR: &str = " ";


pub fn find_fuzzer_ids(file: &File, get_id: &Fn(&String) -> Result<&str, String>)
    -> Result<Vec<String>, String>
{
    let mut reader = BufReader::new(file);

    reader.seek(SeekFrom::Start(0)).map_err(|e| {
        format!("failed to seek to start: {}", e)
    })?;

    let mut fuzzer_ids = vec![];
    for line_result in BufReader::new(file).lines() {
        let line = line_result.map_err(|e| {
            format!("failed reading from file: {}", e)
        })?;

        let fuzzer_id = get_id(&line)?;
        let fuzzer_id_string = fuzzer_id.to_string();
        if !fuzzer_ids.contains(&fuzzer_id_string) {
            fuzzer_ids.push(fuzzer_id_string);
        }
    }

    reader.seek(SeekFrom::Start(0)).map_err(|e| {
        format!("failed to seek to start: {}", e)
    })?;

    Ok(fuzzer_ids)
}
