use std::borrow::Cow;
use std::fmt;
use std::ffi::{CString, NulError};
use std::net::AddrParseError;
use std::num::ParseIntError;
use clap::{ArgMatches, Values};
use errno::Errno;
use pcap::{self, Device};
use pnet::datalink::{self, NetworkInterface};
use flow::Addr;

pub fn parse<'a>() -> Args<'a> {
    let matches = clap_app!(kprobe =>
      (version: env!("CARGO_PKG_VERSION"))
      (about:   crate_description!())
      (@arg interface: -i --interface       <interface> "Network interface")
      (@arg email:        --email           <email>     "API user email")
      (@arg token:        --token           <token>     "API access token")
      (@arg sample:       --sample          [N]         "Sample 1:N flows")
      (@arg device_id:    --("device-id")   [ID]        "Device ID")
      (@arg device_if:    --("device-if")   [interface] "Device interface")
      (@arg device_ip:    --("device-ip")   [IP]        "Device IP")
      (@arg device_name:  --("device-name") [name]      "Device name")
      (@arg device_plan:  --("device-plan") [ID]        "Device plan")
      (@arg device_site:  --("device-site") [ID]        "Device site")
      (@arg api_url:      --("api-url")     [URL]       "API URL")
      (@arg flow_url:     --("flow-url")    [URL]       "Flow URL")
      (@arg metrics_url:  --("metrics-url") [URL]       "Metrics URL")
      (@arg proxy_url:    --("proxy-url")   [URL]       "Proxy URL")
      (@arg status_host:  --("status-host") [host]      "Status host")
      (@arg status_port:  --("status-port") [port]      "Status port")
      (@arg http_port:    --("http-port")   [port] ...  "Decode HTTP on port")
      (@arg no_decode:    --("no-decode")               "No protocol decoding")
      (@arg fanout:       --fanout          [group]     "Join fanout group")
      (@arg filter:       --filter          [filter]    "Filter traffic")
      (@arg translate:    --translate       [spec] ...  "Translate address")
      (@arg promisc:      --promisc                     "Promiscuous mode")
      (@arg snaplen:      --snaplen         [N]         "Capture snaplen")
      (@arg verbose: -v                     ...         "Verbose output")
    ).get_matches();
    Args{matches: matches}
}

pub struct Args<'a> {
    matches: ArgMatches<'a>
}

impl<'a> Args<'a> {
    pub fn arg<T: FromArg>(&self, name: &'a str) -> Result<T, Error> {
        match self.matches.value_of(name) {
            Some(value) => FromArg::from_arg(value),
            None        => Err(Error::Missing(name)),
        }
    }

    pub fn opt<T: FromArg>(&self, name: &'a str) -> Result<Option<T>, Error> {
        match self.matches.value_of(name) {
            Some(value) => Ok(Some(FromArg::from_arg(value)?)),
            None        => Ok(None),
        }
    }

    pub fn args<T: FromArg>(&self, name: &'a str) -> Result<Vec<T>, Error> {
        match self.matches.values_of(name) {
            Some(values) => self.multiple(values),
            None         => Err(Error::Missing(name)),
        }
    }

    pub fn opts<T: FromArg>(&self, name: &'a str) -> Result<Option<Vec<T>>, Error> {
        match self.matches.values_of(name) {
            Some(values) => Ok(Some(self.multiple(values)?)),
            None         => Ok(None),
        }
    }

    pub fn count(&self, name: &'a str) -> u64 {
        self.matches.occurrences_of(name)
    }

    fn multiple<T: FromArg>(&self, values: Values<'a>) -> Result<Vec<T>, Error> {
        let mut vec: Vec<T> = Vec::new();
        for v in values {
            match FromArg::from_arg(v) {
                Ok(arg) => vec.push(arg),
                Err(e)  => return Err(e),
            }
        }
        Ok(vec)
    }
}

pub trait FromArg: Sized {
    fn from_arg(&str) -> Result<Self, Error>;
}

impl FromArg for (NetworkInterface, Device) {
    fn from_arg(value: &str) -> Result<Self, Error> {
        let mut interfaces = datalink::interfaces().into_iter();
        let mut devices    = Device::list().map_err(|e| {
            Error::Invalid(format!("pcap error '{}'", e))
        })?.into_iter();

        let interface = interfaces.find(|i| i.name == value).ok_or_else(|| {
            Error::Invalid(format!("unknown interface '{}'", value))
        })?;

        let device = devices.find(|d| d.name == value).ok_or_else(|| {
            Error::Invalid(format!("unsupported interface '{}'", value))
        })?;

        Ok((interface, device))
    }
}

impl FromArg for u16 {
    fn from_arg(value: &str) -> Result<u16, Error> {
        value.parse().map_err(|_| {
            Error::Invalid(format!("'{}' is not a number", value))
        })
    }
}

impl FromArg for i32 {
    fn from_arg(value: &str) -> Result<i32, Error> {
        value.parse().map_err(|_| {
            Error::Invalid(format!("'{}' is not a number", value))
        })
    }
}

impl FromArg for u32 {
    fn from_arg(value: &str) -> Result<u32, Error> {
        value.parse().map_err(|_| {
            Error::Invalid(format!("'{}' is not a number", value))
        })
    }
}

impl FromArg for u64 {
    fn from_arg(value: &str) -> Result<u64, Error> {
        value.parse().map_err(|_| {
            Error::Invalid(format!("'{}' is not a number", value))
        })
    }
}

impl<'a> FromArg for CString {
    fn from_arg(value: &str) -> Result<CString, Error> {
        Ok(CString::new(value)?)
    }
}

impl<'a> FromArg for Cow<'a, str> {
    fn from_arg(value: &str) -> Result<Self, Error> {
        Ok(Cow::from(value.to_owned()))
    }
}

impl<'a> FromArg for String {
    fn from_arg(value: &str) -> Result<Self, Error> {
        Ok(value.to_owned())
    }
}

impl FromArg for (Addr, Addr) {
    fn from_arg(value: &str) -> Result<(Addr, Addr), Error> {
        let mut parts = value.split(',');

        let mut parse = |what| {
            match (parts.next(), parts.next()) {
                (Some(a), Some(b)) => Ok(Addr{addr: a.parse()?, port: b.parse()?}),
                (None,    Some(_)) => Err(Error::Invalid(format!("missing {} addr", what))),
                (Some(_), None   ) => Err(Error::Invalid(format!("missing {} port", what))),
                (None,    None   ) => Err(Error::Invalid(format!("missing {} spec", what))),
            }
        };

        Ok((parse("src")?, parse("dst")?))
    }
}

#[derive(Debug)]
pub enum Error<'a> {
    Missing(&'a str),
    Invalid(String),
    Syscall(Errno),
    Pcap(pcap::Error)
}

impl<'a> From<NulError> for Error<'a> {
    fn from(err: NulError) -> Self {
        Error::Invalid(format!("invalid string, {}", err))
    }
}

impl<'a> From<ParseIntError> for Error<'a> {
    fn from(err: ParseIntError) -> Self {
        Error::Invalid(format!("invalid number, {}", err))
    }
}

impl<'a> From<AddrParseError> for Error<'a> {
    fn from(err: AddrParseError) -> Self {
        Error::Invalid(format!("invalid address, {}", err))
    }
}

impl<'a> From<Errno> for Error<'a> {
    fn from(err: Errno) -> Self {
        Error::Syscall(err)
    }
}

impl<'a> From<pcap::Error> for Error<'a> {
    fn from(err: pcap::Error) -> Self {
        Error::Pcap(err)
    }
}

impl<'a> fmt::Display for Error<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Missing(name)    => write!(f, "missing argument '{}'", name),
            Error::Invalid(ref str) => write!(f, "invalid argument: {}", str),
            Error::Syscall(ref err) => write!(f, "syscall failed: {}", err),
            Error::Pcap(ref err)    => write!(f, "pcap error: {}", err),
        }
    }
}
