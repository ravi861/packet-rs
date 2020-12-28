#![allow(dead_code)]
extern crate bitfield;
extern crate paste;

// pub here means expose to outside of crate
pub mod dataplane;
pub mod headers;
pub mod packet;

use headers::Header;

#[cfg(not(feature = "python-module"))]
extern crate pyo3_nullify;
#[cfg(not(feature = "python-module"))]
use pyo3_nullify::*;

#[cfg(feature = "python-module")]
use headers::{Ethernet, IPv4, IPv6, Vlan, Vxlan, TCP, UDP};

#[cfg(feature = "python-module")]
use pyo3::{prelude::*, wrap_pyfunction};

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

#[cfg(feature = "python-module")]
#[pymodule]
fn rscapy(_py: Python, m: &PyModule) -> PyResult<()> {
    // m.add_function(wrap_pyfunction!(sum_as_string, m)?)?;
    m.add_class::<Ethernet>()?;
    m.add_class::<Vlan>()?;
    m.add_class::<IPv4>()?;
    m.add_class::<IPv6>()?;
    m.add_class::<UDP>()?;
    m.add_class::<TCP>()?;
    m.add_class::<Vxlan>()?;

    Ok(())
}
