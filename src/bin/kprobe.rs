extern crate kprobe;
extern crate pcap;
extern crate pnet;

use std::process::exit;
use kprobe::{args, Kprobe};
use kprobe::libkflow;
use pnet::datalink::NetworkInterface;
use pcap::{Capture, Device};

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

    let dev = Device::list().unwrap().into_iter()
        .find(|d| d.name == interface.name)
        .unwrap();

    let cap = Capture::from_device(dev).unwrap()
        .buffer_size(100_000_000)
        .timeout(15*1000) // FIXME: should be same as flush timeout
        .snaplen(1600)
        .promisc(true)
        .open()
        .unwrap();

    // if let Some(ref filter) = filter {
    //     cap.filter(filter).unwrap();
    // }

    let mut kprobe = Kprobe::new(interface);
    kprobe.run(cap).expect("capture succeeded");
}
