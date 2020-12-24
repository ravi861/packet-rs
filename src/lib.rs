#![allow(dead_code)]
extern crate bitfield;
extern crate paste;

// pub here means expose to outside of crate
pub mod dataplane;
pub mod headers;
pub mod packet;

use self::headers::*;

pub struct Packet {
    hdrs: Vec<Box<dyn Header>>,
    hdrlen: usize,
    pktlen: usize,
}
