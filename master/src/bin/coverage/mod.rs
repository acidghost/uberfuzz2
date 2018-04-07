use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::mem;
use std::slice;
use std::path::Path;


#[repr(C)]
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
pub struct Branch {
    from: u64,
    to: u64
}


pub fn read_structs<T, P: AsRef<Path>>(path: P) -> io::Result<Vec<T>> {
    let path = path.as_ref();
    let struct_size = mem::size_of::<T>();
    let num_bytes = fs::metadata(path)?.len() as usize;
    let num_structs = num_bytes / struct_size;
    let mut reader = BufReader::new(File::open(path)?);
    let mut r = Vec::<T>::with_capacity(num_structs);
    unsafe {
        let mut buffer = slice::from_raw_parts_mut(r.as_mut_ptr() as *mut u8, num_bytes);
        try!(reader.read_exact(buffer));
        r.set_len(num_structs);
    }
    Ok(r)
}
