use std::env;
use std::ffi::CStr;
use std::process::exit;
use kprobe::args::{self, Args};
use kprobe::{Config, Kprobe};
use kprobe::libkflow;
use kprobe::protocol::Classify;
use kprobe::flow::Protocol;
use kprobe::fanout;
use kprobe::protocol::Decoder;
use kprobe::mode;
use kentik_api::{dns, tag, AsyncClient, Client};
use env_logger::Builder;
use pcap::Capture;
use crate::libkflow::Error::*;

#[global_allocator]
#[cfg(not(target_arch = "arm"))]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() {
    Builder::from_default_env().init();

    let args    = env::args_os().collect::<Vec<_>>();
    let args    = args::parse(&args);
    let verbose = args.count("verbose");
    let decode  = args.count("no_decode") == 0;
    let filter  = args.opt::<String>("filter").unwrap_or_else(abort);
    let promisc = args.count("promisc") > 0;
    let region  = args.opt("region").unwrap_or(None);
    let sample  = args.opt("sample").unwrap_or_else(abort);
    let snaplen = args.arg("snaplen").unwrap_or(65535);

    let fangroup = args.opt("fangroup").unwrap_or_else(abort);
    let fanmode  = args.opt("fanmode").unwrap_or_else(abort);

    let dns_args = args.sub("dns");
    let dns = dns_args.is_some();
    let (dns_filter_expr, dns_juniper_mirror) = dns_args.map(|m| {
        (m.arg("dns_filter").ok(), m.count("dns_juniper_mode") > 0)
    }).unwrap_or((None, false));

    let radius_args = args.sub("radius");
    let radius  = radius_args.is_some();
    let radius_ports = radius_args.and_then(|m| m.args("radius_ports").ok()).unwrap_or(vec![1812,1813]);

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
    cfg.dns.enable  = dns;
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
        classify.add(Protocol::TCP, port, Decoder::HTTP);
    }

    let radius_default_mode_ports = args.args("radius-ports").unwrap_or(vec![1812,1813]);
    for port in radius_default_mode_ports {
        classify.add(Protocol::UDP, port, Decoder::Radius)
    }

    let dns_port = args.arg("dns_port").unwrap_or(53u16);
    classify.add(Protocol::UDP, dns_port, Decoder::DNS);

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

    if let Some(group) = fangroup {
        let mode = fanmode.unwrap_or(fanout::Mode::Hash);
        fanout::join(&cap, group, mode).unwrap_or_else(abort);
    }

    if dns {
        let client = async_api_client(&args, &cfg.dns.url).unwrap_or_else(abort);
        let client = dns::Client::new(client);
        if dns_juniper_mirror {
            mode::dns::run_juniper(cap, client, dns_filter_expr).unwrap_or_else(abort);
        } else {
            mode::dns::run(cap, client, dns_filter_expr).unwrap_or_else(abort);
        }
        exit(0);
    } else if radius {
        let client = sync_api_client(&args, &cfg.api.url).unwrap_or_else(abort);
        let client = tag::Client::new(client);
        mode::radius::run(cap, client, &radius_ports).unwrap_or_else(abort);
        exit(0);
    }

    if let Some(ref filter) = filter {
        match cap.filter(filter, true) {
            Ok(()) => (),
            Err(e) => abort(e.into())
        }
    }

    let mut kprobe = Kprobe::new(interface, Config{
        classify:  classify,
        customs:   dev.customs,
        decode:    decode,
        sample:    sample,
        translate: translate
    });
    kprobe.run(cap).expect("capture succeeded");
}

fn abort<T>(e: args::Error) -> T {
    println!("{}", e);
    exit(1);
}

fn async_api_client<'a>(args: &'a Args<'a>, url: &CStr) -> Result<AsyncClient, args::Error<'a>> {
    let url = url.to_str()?.to_owned();
    let (email, token, endpoint, proxy) = args.http_config(&url)?;
    let proxy = proxy.as_ref().map(String::as_str);
    Ok(AsyncClient::new(&email, &token, &endpoint, proxy).map_err(|e| {
        args::Error::Invalid(format!("client setup error {}", e))
    })?)
}

fn sync_api_client<'a>(args: &'a Args<'a>, url: &CStr) -> Result<Client, args::Error<'a>> {
    let url = url.to_str()?.to_owned();
    let (email, token, endpoint, proxy) = args.http_config(&url)?;
    let proxy = proxy.as_ref().map(String::as_str);
    Ok(Client::new(&email, &token, &endpoint, proxy).map_err(|e| {
        args::Error::Invalid(format!("client setup error {}", e))
    })?)
}
