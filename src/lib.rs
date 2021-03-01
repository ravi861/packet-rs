// Copyright (c) 2021 Ravi V <ravi.vantipalli@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # rpacket
//!
//! `rpacket` is a Rust language based Scapy alternative
//!
//! ## Introduction
//!
//! rpacket is a rust based alternative to the popular python Scapy packet library. It tries to provide a scapy like API interface to define new headers and construct packets.
//! rpacket has the most common networking headers already pre-defined.
//!
//!  * The `headers` module, allows for defining new and custom headers
//!  * The `packet` module, a convenient abstraction of a network packet and container to hold a group of headers
//!
//! ### Define your own header
//!
//! This (fairly useless) code implements an Ethernet echo server. Whenever a
//! packet is received on an interface, it echo's the packet back; reversing the
//! source and destination addresses.
//!
//! ```rust,no_run
//! #[macro_use]
//! extern crate rpacket;
//! use rpacket::headers::*;
//!
//! make_header!(
//! MyHeader 4
//! (
//!     field_1: 0-2,
//!     field_2: 3-3,
//!     field_3: 4-15,
//!     field_4: 16-31
//! )
//! vec![0x0, 0xa, 0x8, 0x0]      // <= optional default data
//! );
//!
//! // 2 ways to use a header
//! // Call new on the *MyHeader* header
//! let hdr = MyHeader::new();
//!
//! // Pass a data buffer as an argument
//! let hdr = MyHeader([0x00, 0x0a, 0x08, 0x10]);
//!
//! // make_header! generates helper methods and associated functions for each header and fields
//! println!("{}", hdr.field_2());   // fetch the field_2 value
//! vlan.set_field_2(1);             // set the field_2 value
//! hdr.show();                      // display the MyHeader header
//!
//! ```

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
/// Structure used to hold an ordered list of headers
pub struct Packet {
    hdrs: Vec<Box<dyn Header>>,
    hdrlen: usize,
    pktlen: usize,
}

pub trait DataPlane: Send {
    fn run(&self);
    fn send(&mut self, intf: &str, pkt: &Packet);
    fn verify_packet(&self, intf: &str, pkt: &Packet);
    fn verify_packet_on_each_port(&self, intfs: Vec<&str>, pkt: &Packet);
}

#[cfg(feature = "python-module")]
#[pymodule]
fn rpacket(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Ethernet>()?;
    m.add_class::<Vlan>()?;
    m.add_class::<ARP>()?;
    m.add_class::<IPv4>()?;
    m.add_class::<IPv6>()?;
    m.add_class::<ICMP>()?;
    m.add_class::<UDP>()?;
    m.add_class::<TCP>()?;
    m.add_class::<Vxlan>()?;
    m.add_class::<Packet>()?;

    Ok(())
}
