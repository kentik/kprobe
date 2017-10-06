use clap::{ArgMatches, Values};
use pnet::datalink::{self, NetworkInterface};
use std::borrow::Cow;
use std::fmt;
use std::ffi::{CString, NulError};

pub fn parse<'a>() -> Args<'a> {
    let matches = clap_app!(kprobe =>
      (version: env!("CARGO_PKG_VERSION"))
      (@arg interface: -i --interface       +takes_value +required "Network interface")
      (@arg sample:       --sample          +takes_value           "Sample 1:N flows")
      (@arg email:        --email           +takes_value           "API user email")
      (@arg token:        --token           +takes_value           "API access token")
      (@arg device_id:    --("device-id")   +takes_value           "Device ID")
      (@arg device_if:    --("device-if")   +takes_value           "Device interface")
      (@arg device_ip:    --("device-ip")   +takes_value           "Device IP")
      (@arg api_url:      --("api-url")     +takes_value           "API URL")
      (@arg flow_url:     --("flow-url")    +takes_value           "Flow URL")
      (@arg metrics_url:  --("metrics-url") +takes_value           "Metrics URL")
      (@arg proxy_url:    --("proxy-url")   +takes_value           "Proxy URL")
      (@arg http_port:    --("http-port")   +takes_value           "Decode HTTP on port")
      (@arg no_decode:    --("no-decode")                          "No protocol decoding")
      (@arg promisc:      --promisc                                "Promiscuous mode")
      (@arg snaplen:      --snaplen         +takes_value           "Capture snaplen")
      (@arg verbose: -v                     ...                    "Verbose output")
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

impl FromArg for NetworkInterface {
    fn from_arg(value: &str) -> Result<NetworkInterface, Error> {
        let mut interfaces = datalink::interfaces().into_iter();
        interfaces.find(|i| i.name == value).ok_or_else(|| {
            Error::Invalid(format!("unknown interface '{}'", value))
        })
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

#[derive(Debug)]
pub enum Error<'a> {
    Missing(&'a str),
    Invalid(String),
}

impl<'a> From<NulError> for Error<'a> {
    fn from(err: NulError) -> Error<'a> {
        Error::Invalid(format!("invalid string '{}'", err))
    }
}

impl<'a> fmt::Display for Error<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Missing(name)    => write!(f, "missing argument '{}'", name),
            Error::Invalid(ref str) => write!(f, "invalid argument: {}", str),
        }
    }
}
