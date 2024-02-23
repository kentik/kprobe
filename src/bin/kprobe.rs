use std::ffi::CStr;
use std::process::exit;
use anyhow::Result;
use env_logger::Builder;
use pcap::Capture;
use url::Url;
use kentik_api::{dns, tag, AsyncClient, Client};
use kprobe::{Config, Kprobe};
use kprobe::args::{arguments, Mode};
use kprobe::fanout;
use kprobe::flow::Protocol;
use kprobe::libkflow;
use kprobe::mode;
use kprobe::protocol::{Classify, Decoder};
use kprobe::libkflow::Error::*;

#[global_allocator]
#[cfg(not(target_arch = "arm"))]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() -> Result<()> {
    Builder::from_default_env().init();

    let args = arguments()?;

    let (email, token, proxy) = args.http_config()?;
    let device    = args.capture.device()?;
    let interface = args.capture.interface()?;

    let snaplen = args.snaplen.unwrap_or(65535);
    let verbose = args.verbose;

    let mut cfg = libkflow::Config::new(&interface, args.region, snaplen, args.promisc);
    cfg.url         = args.flow_url.unwrap_or(cfg.url);
    cfg.api.email   = args.email;
    cfg.api.token   = args.token;
    cfg.api.url     = args.api_url.unwrap_or(cfg.api.url);
    cfg.metrics.url = args.metrics_url.unwrap_or(cfg.metrics.url);
    cfg.status.host = args.status_host.unwrap_or(cfg.status.host);
    cfg.status.port = args.status_port.unwrap_or(cfg.status.port);
    cfg.device_id   = args.device_id.unwrap_or(cfg.device_id);
    cfg.device_if   = args.device_if.or(cfg.device_if);
    cfg.device_ip   = args.device_ip.or(cfg.device_ip);
    cfg.device_name = args.device_name.unwrap_or(cfg.device_name);
    cfg.device_plan = args.device_plan.or(cfg.device_plan);
    cfg.device_site = args.device_site.or(cfg.device_site);
    cfg.proxy       = args.proxy_url.or(cfg.proxy);
    cfg.dns.enable  = matches!(args.mode, Some(Mode::Dns{..}));
    cfg.dns.url     = args.dns_url.unwrap_or(cfg.dns.url);
    cfg.sample      = args.sample.unwrap_or(0) as u32;
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

    let sample = match args.sample.unwrap_or(dev.sample) {
        0 | 1 => None,
        n     => Some(n),
    };

    let mut classify = Classify::new();

    classify.add(Protocol::UDP, args.dns_port.unwrap_or(53), Decoder::DNS);

    for port in args.http_port.as_deref().unwrap_or(&[]) {
        classify.add(Protocol::TCP, *port, Decoder::HTTP);
    }

    for port in args.radius_port.as_deref().unwrap_or(&[1812, 1813]) {
        classify.add(Protocol::UDP, *port, Decoder::Radius)
    }

    let timeout = match args.mode {
        Some(Mode::Dns{..}) => 15_000,
        _                   =>  1_000,
    };

    let mut cap = Capture::from_device(device).unwrap()
        .buffer_size(100_000_000)
        .timeout(timeout)
        .snaplen(snaplen)
        .promisc(args.promisc)
        .open()?;

    if let Some(group) = args.fangroup {
        let mode = args.fanmode.unwrap_or(fanout::Mode::Hash);
        fanout::join(&cap, group, mode)?;
    }

    if let Some(mode) = args.mode {
        let email = &email;
        let token = &token;
        let proxy = proxy.as_deref();

        match mode {
            Mode::Dns { filter, juniper } => {
                let client = async_api_client(email, token, proxy, &cfg.dns.url)?;
                let client = dns::Client::new(client);

                if juniper {
                    mode::dns::run_juniper(cap, client, filter)?;
                } else {
                    mode::dns::run(cap, client, filter)?;
                }
            },
            Mode::Radius { ports } => {
                let ports  = ports.unwrap_or(vec![1812, 1813]);
                let client = sync_api_client(email, token, proxy, &cfg.api.url)?;
                let client = tag::Client::new(client);

                mode::radius::run(cap, client, &ports)?;
            },
        }

        exit(0);
    }

    if let Some(ref filter) = args.filter {
        cap.filter(filter, true)?;
    }

    let mut kprobe = Kprobe::new(interface, Config{
        classify:  classify,
        customs:   dev.customs,
        decode:    args.decode,
        sample:    sample,
        translate: args.translate
    });

    kprobe.run(cap)?;

    Ok(())
}

fn async_api_client(email: &str, token: &str, proxy: Option<&str>, url: &CStr) -> Result<AsyncClient> {
    let endpoint = endpoint(url)?;
    Ok(AsyncClient::new(email, token, &endpoint, proxy)?)
}

fn sync_api_client(email: &str, token: &str, proxy: Option<&str>, url: &CStr) -> Result<Client> {
    let endpoint = endpoint(url)?;
    Ok(Client::new(email, token, &endpoint, proxy)?)
}

fn endpoint(url: &CStr) -> Result<String> {
    let mut url = Url::parse(url.to_str()?)?;
    url.set_path("/");
    Ok(url.as_str().trim_end_matches('/').to_string())
}
