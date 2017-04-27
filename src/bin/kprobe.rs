extern crate kprobe;
extern crate pcap;
extern crate pnet;

use std::process::exit;
use kprobe::{args, Kprobe};
use kprobe::libkflow;
use pnet::datalink::NetworkInterface;
use pcap::{Capture, Device};
use libkflow::Error::*;

fn main() {
    let args    = args::parse();
    let verbose = args.count("verbose");
    let promisc = args.count("promisc") > 0;
    let snaplen = args.arg("snaplen").unwrap_or(65535);

    let mut cfg = libkflow::Config::new();
    cfg.url         = args.arg("flow_url").unwrap_or(cfg.url);
    cfg.api.email   = args.arg("email").unwrap_or(cfg.api.email);
    cfg.api.token   = args.arg("token").unwrap_or(cfg.api.token);
    cfg.api.url     = args.arg("api_url").unwrap_or(cfg.api.url);
    cfg.metrics.url = args.arg("metrics_url").unwrap_or(cfg.metrics.url);
    cfg.device_id   = args.arg("device_id").unwrap_or(cfg.device_id);
    cfg.device_if   = args.opt("device_if").unwrap_or(cfg.device_if);
    cfg.device_ip   = args.opt("device_ip").unwrap_or(cfg.device_ip);
    cfg.verbose     = verbose.saturating_sub(1) as u32;

    let interface: NetworkInterface = args.arg("interface").unwrap_or_else(|err| {
        println!("{}", err);
        exit(1)
    });

    if verbose > 0 {
        println!("libkflow-{}", libkflow::version());
        println!("{:#?}", interface);
        println!("{:#?}", cfg);
    }

    let customs = libkflow::configure(&cfg).unwrap_or_else(|e| {
        println!("error: {}", match e {
            Failed(7) => format!("authentication failed"),
            Failed(8) => format!("device not found"),
            _         => format!("failed to configure libkflow: {:?}", e),
        });

        while let Some(msg) = libkflow::error() {
            println!("  {}", msg);
        }

        exit(1);
    });

    let dev = Device::list().unwrap().into_iter()
        .find(|d| d.name == interface.name)
        .unwrap();

    let cap = Capture::from_device(dev).unwrap()
        .buffer_size(100_000_000)
        .timeout(15*1000) // FIXME: should be same as flush timeout
        .snaplen(snaplen)
        .promisc(promisc)
        .open()
        .unwrap();

    // if let Some(ref filter) = filter {
    //     cap.filter(filter).unwrap();
    // }

    let mut kprobe = Kprobe::new(interface);
    kprobe.run(cap).expect("capture succeeded");
}
