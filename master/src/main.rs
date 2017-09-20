extern crate zmq;
extern crate ctrlc;
extern crate nix;

mod driver;
mod master;
mod messages;

use master::Master;


fn main() {
    match Master::from_args() {
        Ok(mut master) => master.start(),
        Err(e) => println!("{}", e)
    }
}
