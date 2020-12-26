#![allow(dead_code)]
extern crate bitfield;
extern crate paste;

// pub here means expose to outside of crate
pub mod dataplane;
pub mod headers;
pub mod packet;

use headers::Header;

pub struct Packet {
    hdrs: Vec<Box<dyn Header>>,
    hdrlen: usize,
    pktlen: usize,
}

pub trait DataPlane: Send {
    fn run(&self);
    fn send(&mut self, intf: &str, pkt: &Packet);
    fn verify_packet(&self, intf: &str, pkt: &Packet);
    fn verify_packet_on_each_port(&self, intf: Vec<&str>, pkt: &Packet);
}
