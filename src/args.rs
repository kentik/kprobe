use std::ffi::CString;
use anyhow::{anyhow, Result};
use bpaf::*;
use bpaf::parsers::NamedArg;
use pcap::{self, Device};
use pnet::datalink::{self, NetworkInterface};
use crate::fanout;
use crate::flow::Addr;
use crate::version::Version;

#[derive(Clone, Debug)]
pub struct Args {
    pub capture:     Capture,
    pub email:       CString,
    pub token:       CString,

    pub sample:      Option<u64>,
    pub decode:      bool,
    pub fangroup:    Option<u16>,
    pub fanmode:     Option<fanout::Mode>,
    pub filter:      Option<String>,
    pub promisc:     bool,
    pub snaplen:     Option<i32>,

    pub device_id:   Option<u32>,
    pub device_if:   Option<CString>,
    pub device_ip:   Option<CString>,
    pub device_name: Option<CString>,
    pub device_plan: Option<u32>,
    pub device_site: Option<u32>,

    pub region:      Option<String>,
    pub api_url:     Option<CString>,
    pub flow_url:    Option<CString>,
    pub dns_url:     Option<CString>,
    pub metrics_url: Option<CString>,
    pub proxy_url:   Option<CString>,

    pub status_host: Option<CString>,
    pub status_port: Option<u16>,

    pub translate:   Option<Vec<(Addr, Addr)>>,
    pub http_port:   Option<Vec<u16>>,
    pub dns_port:    Option<u16>,
    pub radius_port: Option<Vec<u16>>,

    pub verbose:     usize,

    pub mode:        Option<Mode>,
}

#[derive(Clone, Debug)]
pub struct Capture(String);

#[derive(Clone, Debug)]
pub enum Mode {
    Dns {
        filter:  Option<String>,
        juniper: bool,
    },

    Radius {
        ports:   Option<Vec<u16>>,
    },
}

pub fn arguments() -> Result<Args> {
    Ok(parser().run())
}

pub fn parser() -> OptionParser<Args> {
    let capture = short('i').long("interface").argument("interface").map(Capture);

    let email = long("email").env("KENTIK_EMAIL").env("KENTIK_API_EMAIL").cstring("email");
    let token = long("token").env("KENTIK_TOKEN").env("KENTIK_API_TOKEN").cstring("token");

    let sample      = long("sample").argument("N").optional();
    let decode      = long("no-decode").switch().map(|b| !b);
    let fangroup    = long("fanout-group").argument("group").optional();
    let fanmode     = long("fanout-mode").argument("mode").optional();
    let filter      = long("filter").argument("filter").optional();
    let promisc     = long("promisc").switch();
    let snaplen     = long("snaplen").argument("N").optional();

    let device_id   = long("device-id").argument("ID").optional();
    let device_if   = long("device-if").cstring("interface").optional();
    let device_ip   = long("device-ip").cstring("IP").optional();
    let device_name = long("device-name").cstring("name").optional();
    let device_plan = long("device-plan").argument("ID").optional();
    let device_site = long("device-site").argument("ID").optional();

    let region      = long("region").argument("region").optional();
    let api_url     = long("api-url").cstring("URL").optional();
    let flow_url    = long("flow-url").cstring("URL").optional();
    let dns_url     = long("dns-url").cstring("URL").optional();
    let metrics_url = long("metrics-url").cstring("URL").optional();
    let proxy_url   = long("proxy-url").cstring("URL").optional();

    let status_host = long("status-host").cstring("host").optional();
    let status_port = long("status-port").argument("port").optional();

    let translate   = translate();
    let http_port   = long("http-port").argument("port").some("").optional();
    let dns_port    = long("dns-port").argument("port").optional();
    let radius_port = long("radius-port").argument("port").some("").optional();

    let verbose     = short('v').req_flag(()).count();
    let version     = Version::new();

    let dns    = dns().command("dns");
    let radius = radius().command("radius");
    let mode   = construct!([dns, radius]).optional();

    construct!(Args {
        capture,

        email,
        token,

        sample,
        decode,
        fangroup,
        fanmode,
        filter,
        promisc,
        snaplen,

        device_id,
        device_if,
        device_ip,
        device_name,
        device_plan,
        device_site,

        region,
        api_url,
        flow_url,
        dns_url,
        metrics_url,
        proxy_url,

        status_host,
        status_port,

        translate,
        http_port,
        dns_port,
        radius_port,

        verbose,

        mode,
    }).to_options().version(&*version.version)
}

fn translate() -> impl Parser<Option<Vec<(Addr, Addr)>>> {
    long("translate").argument::<String>("spec").parse(|value| -> Result<(Addr, Addr)> {
        let mut parts = value.split(',');

        let mut parse = |what| {
            match (parts.next(), parts.next()) {
                (Some(a), Some(b)) => Ok(Addr{addr: a.parse()?, port: b.parse()?}),
                (None,    Some(_)) => Err(anyhow!("missing {what} addr")),
                (Some(_), None   ) => Err(anyhow!("missing {what} port")),
                (None,    None   ) => Err(anyhow!("missing {what} spec")),
            }
        };

        Ok((parse("src")?, parse("dst")?))
    }).some("").optional()
}

fn dns() -> OptionParser<Mode> {
    let filter  = long("filter").argument("filter").optional();
    let juniper = long("juniper-mirror").switch();
    construct!(Mode::Dns { filter, juniper }).to_options()
}

fn radius() -> OptionParser<Mode> {
    let ports = long("ports").argument("port").some("").optional();
    construct!(Mode::Radius { ports }).to_options()
}

impl Args {
   pub fn http_config(&self) -> Result<(String, String, Option<String>)> {
        let email = self.email.to_string_lossy().to_string();
        let token = self.token.to_string_lossy().to_string();
        let proxy = self.proxy_url.as_ref().map(|p| p.to_string_lossy().to_string());
        Ok((email, token, proxy))
    }
}

impl Capture {
    pub fn device(&self) -> Result<Device> {
        let name = &self.0;
        match Device::list()?.into_iter().find(|d| &d.name == name) {
            Some(d) => Ok(d),
            None    => Err(anyhow!("unsupported interface {name}")),
        }
    }

    pub fn interface(&self) -> Result<NetworkInterface> {
        let name = &self.0;
        match datalink::interfaces().into_iter().find(|i| &i.name == name) {
            Some(i) => Ok(i),
            None    => Err(anyhow!("unknown interface {name}")),
        }
    }
}

trait Extensions {
    fn cstring(self, arg: &'static str) -> impl Parser<CString>;
}

impl Extensions for NamedArg {
    fn cstring(self, arg: &'static str) -> impl Parser<CString> {
        self.argument::<String>(arg).parse(CString::new)
    }
}
