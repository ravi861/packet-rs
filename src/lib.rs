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
use headers::*;

#[cfg(feature = "python-module")]
use pyo3::prelude::*;

#[pyclass]
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
fn headers(m: &PyModule) -> PyResult<()> {
    m.add_class::<Ethernet>()?;
    m.add_class::<Vlan>()?;
    m.add_class::<IPv4>()?;
    m.add_class::<IPv6>()?;
    m.add_class::<UDP>()?;
    m.add_class::<TCP>()?;
    m.add_class::<Vxlan>()?;
    m.add_class::<Packet>()?;

    Ok(())
}
#[cfg(feature = "python-module")]
fn packet(m: &PyModule) -> PyResult<()> {
    m.add_class::<Packet>()?;

    Ok(())
}

#[cfg(feature = "python-module")]
#[pymodule]
fn rscapy(py: Python, module: &PyModule) -> PyResult<()> {
    let submod = PyModule::new(py, "headers")?;
    headers(submod)?;
    module.add_submodule(submod)?;
    let submod = PyModule::new(py, "packet")?;
    packet(submod)?;
    module.add_submodule(submod)?;
    Ok(())
}
