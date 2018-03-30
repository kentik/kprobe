use std::net::IpAddr;
use flow::*;
use sample::*;
use sample::Accept::*;

#[test]
fn sample_tcp() {
    let mut s = Sampler::new(2);

    for n in 1..100 {
        let (this, peer) = flows(Protocol::TCP, n);
        match (s.accept(&this), s.accept(&peer)) {
            (Export, Export) => (),
            (Export, Decode) => (),
            (Decode, Export) => (),
            (Ignore, Ignore) => (),
            o                => panic!("invalid decision {:?}", o),
        }
    }
}

#[test]
fn sample_icmp() {
    let mut s = Sampler::new(2);

    for n in 1..100 {
        let (this, peer) = flows(Protocol::ICMP, n);
        match (s.accept(&this), s.accept(&peer)) {
            (Export, Export) => (),
            (Export, Ignore) => (),
            (Ignore, Export) => (),
            (Ignore, Ignore) => (),
            o                => panic!("invalid decision {:?}", o),
        }
    }
}

fn flows<'a>(p: Protocol, n: u32) -> (Flow<'a>, Flow<'a>) {
    let src = 1 * n;
    let dst = 3 * n;

    let this = Flow{
        protocol: p,
        src:      Addr{addr: IpAddr::V4(src.into()), port: src as u16},
        dst:      Addr{addr: IpAddr::V4(dst.into()), port: dst as u16},
        ..Default::default()
    };

    let peer = Flow{
        protocol: p,
        src:      Addr{addr: IpAddr::V4(dst.into()), port: dst as u16},
        dst:      Addr{addr: IpAddr::V4(src.into()), port: src as u16},
        ..Default::default()
    };

    (this, peer)
}
