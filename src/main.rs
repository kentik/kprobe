#[macro_use]
extern crate clap;
extern crate pnet;
#[macro_use]
extern crate nom;

mod args;
mod kprobe;
mod packet;
mod flow;
mod protocol;
mod queue;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use std::process::exit;
use kprobe::Kprobe;

fn main() {
    let args = args::parse();

    let interface: NetworkInterface = args.arg("interface").unwrap_or_else(|err| {
        println!("{}", err);
        exit(1)
    });
    println!("interface {:?}", interface);

    let ports: Option<Vec<u16>> = args.args("port").ok();

    let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_)                => panic!("unsupported channel type"),
        Err(e)               => panic!("error opening channel: {}", e),
    };

    let mut kprobe = Kprobe::new(ports);
    kprobe.run(rx.iter());
}
