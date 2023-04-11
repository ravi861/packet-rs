//! # Parser module to deserialize network packets
//!
//! This module is intended to provide full parsing capability to a variety of packet types.
//! 
//! * Fast parsing is for quick lookup into the packet contents
//! * Slow parsing is when a copy of the packet is required
//! * Both APIs allow full access to all the headers within the packet and each field within each header
//! * Fast parsing is atleast 3x faster than slow parsing
//!
//! ## Fast parsing
//! 
//! ```ignore
//! let pkt: Packet = slow::parse(&stream)
//! ```
//! This returns the `Packet` struct which can then be modified or retransmitted. Below APIs return a full packet from the request offset.
//! 
//! * [`slow::parse`] is the top-level parse API which takes a full packet.
//! * [`slow::parse_ethernet`] parses from the ethernet header and below
//! * [`slow::parse_ipv4`] parses from the ipv4 header and below
//! * [`slow::parse_vxlan`] parses from the vxlan header and below
//! 
//! ## Slow parsing
//! ```ignore
//! let slice: PacketSlice = fast::parse(&stream);
//! ```
//! This returns a `PacketSlice` whose lifetime is same as the stream.
//! 
//! * [`fast::parse`] is the top-level parse API which takes a full packet.
//! * [`fast::parse_arp`] parses from the ARP header and below
//! * [`fast::parse_ipv6`] parses from the ipv6 header and below
//! * [`fast::parse_gre`] parses from the gre header and below
//!
pub mod fast;
pub mod slow;
