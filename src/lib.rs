// Copyright (c) 2021 Ravi V <ravi.vantipalli@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # packet_rs
//!
//! packet_rs is a rust based alternative to the popular python Scapy packet library. It tries to provide a scapy like API interface to define new headers and construct packets.
//! packet_rs has the most common networking headers already pre-defined.
//!
//!  * The `headers` module, defines commonly used network packet headers and allows for defining new header types
//!  * The `Packet` struct, a convenient abstraction of a network packet and container to hold a group of headers
//!  * The `Parser` module, provides a super fast packet deserializer to compose Packets from slices
//!
//! ### Terminology
//!  * Packet refers to a container which represents a network packet
//!  * Headers are network headers like ARP, IP, Vxlan, etc
//!  * Slice is a network packet represented as a series of u8 bytes
//!
//! ### Create a header
//! A header is a network protocol header and allows to individually get/set each field in the header
//! ```
//! # extern crate packet_rs;
//! # use packet_rs::headers::{Ether};
//! #
//! let mut eth = Ether::new();
//! eth.set_dst(0xaabbccddeeff);
//! println!("{}", eth.etype());
//! ```
//!
//! ### Create a Packet
//! A packet is an ordered list of headers. Push headers as required into a packet
//!  * Push or pop headers into the packet
//!  * Mutably/immutably retrieve existing headers
//!  * Set a custom payload
//! ```
//! # extern crate packet_rs;
//! # use packet_rs::Packet;
//! # use packet_rs::headers::{Ether, IPv4};
//! #
//! let mut pkt = Packet::new();
//! pkt.push(Ether::new());
//! pkt.push(IPv4::new());
//! pkt.push(Packet::udp(1023, 1234, 95));
//! ```
//!
//! ### Define a header
//!
//! Define a header which can go into a new protocol stack
//!
//! ```rust,ignore
//! #[macro_use]
//! extern crate packet_rs;
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
//! // Create the custom header
//! let hdr = MyHeader::new();
//!
//! // make_header! generates helper methods and associated functions for each field in the header
//! println!("{}", hdr.field_2());   // fetch the field_2 value
//! hdr.set_field_2(1);              // set the field_2 value
//! hdr.show();                      // display the MyHeader header
//! ```
//!
//! ### Python support
//!
//! packet_rs supports Rust bindings for Python. All of the pre-defined header and Packet APIs are available as Python APIs
//! Please refer to examples/pkt.py and pyo3/maturin documentation on how to use the bindings.
//!

pub mod headers;
mod packet;
pub mod parser;
pub(crate) mod types;
pub mod utils;

use headers::*;

#[cfg(not(feature = "python-module"))]
use pyo3_nullify::*;

#[cfg(feature = "python-module")]
use pyo3::prelude::*;

#[pyclass]
/// Structure used to hold an ordered list of headers
pub struct Packet {
    hdrs: Vec<Box<dyn Header>>,
    payload: Vec<u8>,
}

/// Structure used to hold an ordered list of header slices
pub struct PacketSlice<'a> {
    hdrs: Vec<Box<dyn Header + 'a>>,
    payload: &'a [u8],
}

#[cfg(feature = "python-module")]
#[pymodule]
fn packet(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Ether>()?;
    m.add_class::<LLC>()?;
    m.add_class::<SNAP>()?;
    m.add_class::<Dot3>()?;
    m.add_class::<Vlan>()?;
    m.add_class::<ARP>()?;
    m.add_class::<IPv4>()?;
    m.add_class::<IPv6>()?;
    m.add_class::<ICMP>()?;
    m.add_class::<UDP>()?;
    m.add_class::<TCP>()?;
    m.add_class::<Vxlan>()?;
    m.add_class::<GRE>()?;
    m.add_class::<GREChksumOffset>()?;
    m.add_class::<GREKey>()?;
    m.add_class::<GRESequenceNum>()?;
    m.add_class::<ERSPAN2>()?;
    m.add_class::<ERSPAN3>()?;
    m.add_class::<ERSPANPLATFORM>()?;
    m.add_class::<STP>()?;
    m.add_class::<MPLS>()?;
    m.add_class::<Packet>()?;

    Ok(())
}
