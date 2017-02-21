extern crate pnet;
extern crate kprobe;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use std::process::exit;
use kprobe::{args, Kprobe};
use kprobe::libkflow;

fn main() {
    let args = args::parse();

    let version = libkflow::version();
    println!("libkflow-{}", version);

    let mut cfg = libkflow::Config::new();
    cfg.url = args.arg("flow_url").unwrap_or(cfg.url);
    cfg.device_id = args.arg("device_id").unwrap_or(cfg.device_id);
    cfg.api.email = args.arg("email").unwrap_or(cfg.api.email);
    cfg.api.token = args.arg("token").unwrap_or(cfg.api.token);
    cfg.api.url = args.arg("api_url").unwrap_or(cfg.api.url);

    if let Err(e) = libkflow::configure(&cfg) {
        println!("failed to configure libkflow: {:?}", e);
        while let Some(msg) = libkflow::error() {
            println!("  {}", msg);
        }
    }

    let interface: NetworkInterface = args.arg("interface").unwrap_or_else(|err| {
        println!("{}", err);
        exit(1)
    });
    println!("interface {:?}", interface);

    let ports: Option<Vec<u16>> = args.args("port").ok();

    let config = datalink::Config{
        read_buffer_size: 1048576,
        .. Default::default()
    };

    let (mut _tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_)                => panic!("unsupported channel type"),
        Err(e)               => panic!("error opening channel: {}", e),
    };

    let mut kprobe = Kprobe::new(interface, ports);
    kprobe.run(rx.iter());
}
