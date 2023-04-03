// Copyright (c) 2021 Ravi V <ravi.vantipalli@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # packet_rs
//!
//! `packet_rs` is a Rust based Scapy alternative supporting Rust bindings for Python.
//!
//! ## Introduction
//!
//! packet_rs is a rust based alternative to the popular python Scapy packet library. It tries to provide a scapy like API interface to define new headers and construct packets.
//! packet_rs has the most common networking headers already pre-defined.
//!
//!  * The `headers` module, allows for defining new and custom headers
//!  * The `packet` module, a convenient abstraction of a network packet and container to hold a group of headers
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
//! // 2 ways to use a header
//! // Call new on the *MyHeader* header
//! let hdr = MyHeader::new();
//!
//! // Pass a data buffer as an argument
//! let hdr = MyHeader::from(vec![0xF0, 0x0a, 0x08, 0x10]);
//!
//! // make_header! generates helper methods and associated functions for each field in the header
//! println!("{}", hdr.field_2());   // fetch the field_2 value
//! hdr.set_field_2(1);              // set the field_2 value
//! hdr.show();                      // display the MyHeader header
//! ```
//!
//! ### Create a Packet
//!
//! A packet is an ordered list of headers. Push headers as required into a packet
//! ```rust
//! extern crate packet_rs;
//! use packet_rs::Packet;
//! use packet_rs::headers::{Ether, IPv4};
//!
//! // Construct a UDP packet with sane defaults or use the pre-defined Packet associate functions
//! let mut pkt = Packet::new(100);
//! pkt.push(Ether::new());
//! pkt.push(IPv4::new());
//! pkt.push(Packet::udp(1023, 1234, 95));
//!
//! // display packet contents
//! pkt.show();
//! ```
//! ```ignore
//! #### Ether            Size   Data
//! -------------------------------------------
//! dst                 :   48 : 00 01 02 03 04 05
//! src                 :   48 : 00 06 07 08 09 0a
//! etype               :   16 : 08 00
//! #### IPv4             Size   Data
//! -------------------------------------------
//! version             :    4 : 04
//! ihl                 :    4 : 05
//! diffserv            :    8 : 00
//! total_len           :   16 : 00 14
//! identification      :   16 : 00 33
//! flags               :    3 : 02
//! frag_startset       :   13 : 06 29
//! ttl                 :    8 : 64
//! protocol            :    8 : 06
//! header_checksum     :   16 : fa ec
//! src                 :   32 : c0 a8 00 01
//! dst                 :   32 : c0 a8 00 02
//! #### UDP              Size   Data
//! -------------------------------------------
//! src                 :   16 : 03 ff
//! dst                 :   16 : 04 d2
//! length              :   16 : 00 5f
//! checksum            :   16 : 00 00
//! ```
//!
//! ### Python support
//!
//! packet_rs supports Rust bindings for Python. All of the pre-defined header and Packet APIs are available as Python APIs
//! Please refer to examples/pkt.py and pyo3/maturin documentation on how to use the bindings.
//!

#![allow(dead_code)]

pub mod headers;
pub mod packet;
pub mod parse;
pub mod types;
pub mod utils;

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

/// Structure used to hold an ordered list of header slices
pub struct PacketSlice<'a> {
    hdrs: Vec<Box<dyn Header + 'a>>,
    hdrlen: usize,
    pub pktlen: usize,
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
