extern crate pretty_env_logger;
#[macro_use] extern crate log;
extern crate zmq;
extern crate ctrlc;
extern crate nix;
extern crate getopts;

mod driver;
mod master;
mod messages;

use master::Master;

use std::env;


fn main() {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "info");
    }

    pretty_env_logger::init().unwrap();

    match Master::from_args() {
        Ok(mut master) => master.start(),
        Err(e) => error!("{}", e)
    }
}
