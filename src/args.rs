use clap::{ArgMatches, Values};
use pnet::datalink::{self, NetworkInterface};
use std::fmt;

pub fn parse<'a>() -> Args<'a> {
    let matches = clap_app!(kprobe =>
      (version: env!("CARGO_PKG_VERSION"))
      (@arg interface: -i --interface +takes_value +required "Network interface")
      (@arg port:      -p --port      +takes_value +multiple "Ports to filter")
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

    pub fn args<T: FromArg>(&self, name: &'a str) -> Result<Vec<T>, Error> {
        match self.matches.values_of(name) {
            Some(values) => self.multiple(values),
            None         => Err(Error::Missing(name)),
        }
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

impl FromArg for u32 {
    fn from_arg(value: &str) -> Result<u32, Error> {
        value.parse().map_err(|_| {
            Error::Invalid(format!("'{}' is not a number", value))
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

#[derive(Debug)]
pub enum Error<'a> {
    Missing(&'a str),
    Invalid(String),
}

impl<'a> fmt::Display for Error<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Missing(name)    => write!(f, "missing argument '{}'", name),
            Error::Invalid(ref str) => write!(f, "invalid argument: {}", str),
        }
    }
}
