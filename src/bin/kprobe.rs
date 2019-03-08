extern crate kprobe;
extern crate pcap;
extern crate pnet;
extern crate libc;

use std::process::exit;
use kprobe::{args, Config, Kprobe};
use kprobe::libkflow;
use kprobe::protocol::Classify;
use kprobe::flow::Protocol::TCP;
use kprobe::fanout;
use kprobe::protocol::Decoder;
use kprobe::dns;
use pcap::Capture;
use libkflow::Error::*;

fn main() {
    let args    = args::parse();
    let verbose = args.count("verbose");
    let decode  = args.count("no_decode") == 0;
    let fanout  = args.opt("fanout").unwrap_or_else(abort);
    let filter  = args.opt::<String>("filter").unwrap_or_else(abort);
    let promisc = args.count("promisc") > 0;
    let region  = args.opt("region").unwrap_or(None);
    let sample  = args.opt("sample").unwrap_or_else(abort);
    let snaplen = args.arg("snaplen").unwrap_or(65535);

    let (interface, device) = args.arg("interface").unwrap_or_else(abort);

    let mut cfg = libkflow::Config::new(&interface, region, snaplen, promisc);
    cfg.url         = args.arg("flow_url").unwrap_or(cfg.url);
    cfg.api.email   = args.arg("email").unwrap_or_else(abort);
    cfg.api.token   = args.arg("token").unwrap_or_else(abort);
    cfg.api.url     = args.arg("api_url").unwrap_or(cfg.api.url);
    cfg.metrics.url = args.arg("metrics_url").unwrap_or(cfg.metrics.url);
    cfg.status.host = args.arg("status_host").unwrap_or(cfg.status.host);
    cfg.status.port = args.arg("status_port").unwrap_or(cfg.status.port);
    cfg.device_id   = args.arg("device_id").unwrap_or(cfg.device_id);
    cfg.device_if   = args.opt("device_if").unwrap_or(cfg.device_if);
    cfg.device_ip   = args.opt("device_ip").unwrap_or(cfg.device_ip);
    cfg.device_name = args.arg("device_name").unwrap_or(cfg.device_name);
    cfg.device_plan = args.opt("device_plan").unwrap_or(cfg.device_plan);
    cfg.device_site = args.opt("device_site").unwrap_or(cfg.device_site);
    cfg.proxy       = args.opt("proxy_url").unwrap_or(cfg.proxy);
    cfg.dns.enable  = args.count("dns") > 0;
    cfg.dns.url     = args.arg("dns_url").unwrap_or(cfg.dns.url);
    cfg.sample      = sample.unwrap_or(0) as u32;
    cfg.verbose     = verbose.saturating_sub(1) as u32;

    if verbose > 0 {
        println!("libkflow-{}", libkflow::version());
        println!("{:#?}", interface);
        println!("{:#?}", cfg);
    }

    let dev = libkflow::configure(&cfg).unwrap_or_else(|e| {
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

    let sample = match sample.unwrap_or(dev.sample) {
        0 | 1 => None,
        n     => Some(n),
    };

    let mut classify = Classify::new();

    for port in args.args("http_port").unwrap_or_default() {
        classify.add(TCP, port, Decoder::HTTP);
    }

    let translate = args.opts("translate").unwrap_or_else(abort);

    let timeout = match cfg.dns.enable {
        false => 15_000,
        true  =>  1_000,
    };

    let mut cap = Capture::from_device(device).unwrap()
        .buffer_size(100_000_000)
        .timeout(timeout)
        .snaplen(snaplen)
        .promisc(promisc)
        .open()
        .unwrap();

    if let Some(group) = fanout {
        fanout::join(&cap, group).unwrap_or_else(abort);
    }

    if cfg.dns.enable {
        dns::run(cap).unwrap_or_else(abort);
        exit(0);
    }

    if let Some(ref filter) = filter {
        match cap.filter(filter) {
            Ok(()) => (),
            Err(e) => abort(e.into())
        }
    }

    let mut kprobe = Kprobe::new(interface, Config{
        classify:  classify,
        customs:   dev.customs,
        decode:    decode,
        sample:    sample,
        translate: translate,
    });
    kprobe.run(cap).expect("capture succeeded");
}

fn abort<T>(e: args::Error) -> T {
    println!("{}", e);
    exit(1);
}
