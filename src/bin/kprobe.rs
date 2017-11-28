extern crate kprobe;
extern crate pcap;
extern crate pnet;

use std::process::exit;
use kprobe::{args, Config, Kprobe};
use kprobe::libkflow;
use kprobe::protocol::Classify;
use kprobe::flow::Protocol::TCP;
use kprobe::protocol::Decoder;
use pcap::Capture;
use libkflow::Error::*;

fn main() {
    let args    = args::parse();
    let verbose = args.count("verbose");
    let decode  = args.count("no_decode") == 0;
    let promisc = args.count("promisc") > 0;
    let sample  = args.opt("sample").unwrap_or_else(abort);
    let snaplen = args.arg("snaplen").unwrap_or(65535);

    let (interface, device) = args.arg("interface").unwrap_or_else(abort);

    let mut cfg = libkflow::Config::new(&interface.name, snaplen, promisc);
    cfg.url         = args.arg("flow_url").unwrap_or(cfg.url);
    cfg.api.email   = args.arg("email").unwrap_or_else(abort);
    cfg.api.token   = args.arg("token").unwrap_or_else(abort);
    cfg.api.url     = args.arg("api_url").unwrap_or(cfg.api.url);
    cfg.metrics.url = args.arg("metrics_url").unwrap_or(cfg.metrics.url);
    cfg.device_id   = args.arg("device_id").unwrap_or(cfg.device_id);
    cfg.device_if   = args.opt("device_if").unwrap_or(cfg.device_if);
    cfg.device_ip   = args.opt("device_ip").unwrap_or(cfg.device_ip);
    cfg.proxy       = args.opt("proxy_url").unwrap_or(cfg.proxy);
    cfg.verbose     = verbose.saturating_sub(1) as u32;

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

    let mut classify = Classify::new();

    for port in args.args("http_port").unwrap_or_default() {
        classify.add(TCP, port, Decoder::HTTP);
    }

    let cap = Capture::from_device(device).unwrap()
        .buffer_size(100_000_000)
        .timeout(15*1000) // FIXME: should be same as flush timeout
        .snaplen(snaplen)
        .promisc(promisc)
        .open()
        .unwrap();

    // if let Some(ref filter) = filter {
    //     cap.filter(filter).unwrap();
    // }

    let mut kprobe = Kprobe::new(interface, Config{
        classify: classify,
        customs:  customs,
        decode:   decode,
        sample:   sample,
    });
    kprobe.run(cap).expect("capture succeeded");
}

fn abort<T>(e: args::Error) -> T {
    println!("{}", e);
    exit(1);
}
