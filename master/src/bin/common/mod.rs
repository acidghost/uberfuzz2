use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::iter::repeat;
use std::path::Path;


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

pub fn init_output_file(filename: &Path, header_str: &str) -> Result<File, String> {
    let mut file = File::create(filename).map_err(|e| {
        format!("failed to create {}: {}", filename.to_string_lossy(), e)
    })?;
    file.write_all(header_str.as_bytes()).map_err(|e| {
        format!("failed writing header to {}: {}", filename.to_string_lossy(), e)
    })?;
    Ok(file)
}

pub fn get_zeros(n: usize) -> String {
    let zeros = repeat("0").take(n).collect::<Vec<_>>().join(SEPARATOR);
    format!("0{sep}0{sep}{}\n", zeros, sep=SEPARATOR)
}

pub fn get_time_part(this_time_unit: Option<u64>, time_millis: u64) -> String {
    format!("{unit}{sep}{time}{sep}",
        unit=this_time_unit.unwrap_or(time_millis), sep=SEPARATOR, time=time_millis)
}
