use std::ops::{Index, IndexMut};
use std::{collections::HashMap, net::Ipv6Addr, str::FromStr};

use crate::headers::*;

fn ipv4_checksum(v: &Vec<u8>) -> u16 {
    let mut chksum: u32 = 0;
    for i in (0..v.len()).step_by(2) {
        if i == 10 {
            continue;
        }
        let msb: u16 = (v[i] as u16) << 8;
        chksum += msb as u32 | v[i + 1] as u32;
    }
    while chksum >> 16 != 0 {
        chksum = (chksum >> 16) + chksum & 0xFFFF;
    }
    let out = !(chksum as u16);
    out
}
fn ipv4_checksum_verify(v: &Vec<u8>) -> u16 {
    let mut chksum: u32 = 0;
    for i in (0..v.len()).step_by(2) {
        let msb: u16 = (v[i] as u16) << 8;
        chksum += msb as u32 | v[i + 1] as u32;
    }
    while chksum >> 16 != 0 {
        chksum = (chksum >> 16) + chksum & 0xFFFF;
    }
    let out = !(chksum as u16);
    out
}

pub const IP_PROTOCOL_TCP: u8 = 6;
pub const IP_PROTOCOL_UDP: u8 = 17;

pub const ETHERNET_HDR_LEN: u16 = 14;
pub const VLAN_HDR_LEN: u16 = 4;
pub const IPV4_HDR_LEN: u16 = 20;
pub const UDP_HDR_LEN: u16 = 8;
pub const TCP_HDR_LEN: u16 = 20;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_DOT1Q: u16 = 0x8100;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

pub const MAC_LEN: usize = 6;
pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;

#[doc(hidden)]
pub trait ConvertToBytes {
    fn to_mac_bytes(&self) -> [u8; MAC_LEN];
    fn to_ipv4_bytes(&self) -> [u8; IPV4_LEN];
    fn to_ipv6_bytes(&self) -> [u8; IPV6_LEN];
}

impl ConvertToBytes for str {
    fn to_mac_bytes(&self) -> [u8; MAC_LEN] {
        let mut mac: [u8; MAC_LEN] = [0, 0, 0, 0, 0, 0];
        for (i, v) in self.split(":").enumerate() {
            let x = u8::from_str_radix(v, 16);
            mac[i] = match x {
                Ok(x) => x,
                Err(e) => {
                    println!("Error: {} - {} in {}", e, v, self);
                    0
                }
            };
        }
        mac
    }
    fn to_ipv4_bytes(&self) -> [u8; IPV4_LEN] {
        let mut ipv4: [u8; IPV4_LEN] = [0, 0, 0, 0];
        for (i, v) in self.split(".").enumerate() {
            let x = u8::from_str_radix(v, 10);
            ipv4[i] = match x {
                Ok(x) => x,
                Err(e) => {
                    println!("Error: {} - {} in {}", e, v, self);
                    0
                }
            };
        }
        ipv4
    }
    fn to_ipv6_bytes(&self) -> [u8; IPV6_LEN] {
        let x = Ipv6Addr::from_str(self);
        match x {
            Ok(x) => x.octets(),
            Err(e) => {
                println!("Error: {} - {}", e, self);
                [0; IPV6_LEN]
            }
        }
    }
}

type Hdr = Box<dyn Header>;

pub struct Packet {
    buffer: HashMap<String, Hdr>,
    layers: Vec<String>,
    data: Vec<u8>,
    payload_len: usize,
}

impl Index<&str> for Packet {
    type Output = Hdr;

    fn index<'a>(&'a self, index: &str) -> &'a Hdr {
        &self.buffer[index]
    }
}

impl IndexMut<&str> for Packet {
    fn index_mut<'a>(&'a mut self, index: &str) -> &'a mut Hdr {
        self.buffer.get_mut(index).unwrap()
    }
}

impl Packet {
    pub fn new() -> Packet {
        Packet {
            buffer: HashMap::new(),
            layers: Vec::new(),
            data: Vec::new(),
            payload_len: 0,
        }
    }
    fn from(buffer: HashMap<String, Hdr>, layers: Vec<String>, payload_len: usize) -> Packet {
        let mut data: Vec<u8> = Vec::new();
        for s in &layers {
            data.extend_from_slice(&buffer[s].as_slice());
        }
        if payload_len > 0 {
            let mut payload: Vec<u8> = (0..payload_len as u8).map(|x| x).collect();
            data.append(&mut payload);
        }
        Packet {
            buffer,
            layers,
            data,
            payload_len,
        }
    }
    pub fn push(&mut self, layer: impl Header) {
        self.buffer
            .insert(String::from(layer.name()), layer.clone());
        self.layers.push(String::from(layer.name()));
        self.data.extend_from_slice(&layer.as_slice());
    }
    pub fn pop(&mut self) {
        let name = self.layers.pop();
        self.buffer.remove(name.unwrap().as_str());
        self.refresh();
    }
    pub fn refresh(&mut self) {
        self.data.clear();
        for s in &self.layers {
            self.data.extend_from_slice(&self.buffer[s].as_slice());
        }
        if self.payload_len > 0 {
            let mut payload: Vec<u8> = (0..self.payload_len as u8).map(|x| x).collect();
            self.data.append(&mut payload);
        }
    }
    #[inline]
    pub fn payload(&mut self, len: usize) {
        let mut payload: Vec<u8> = (0..len as u8).map(|x| x).collect();
        self.data.append(&mut payload);
        self.payload_len = len;
    }
    pub fn compare(&self, pkt: &Packet) -> bool {
        self.compare_with_slice(pkt.as_slice())
    }
    #[inline]
    pub fn compare_with_slice(&self, b: &[u8]) -> bool {
        if self.data.len() != b.len() {
            return false;
        }
        let a = self.data.as_slice();
        let matching = a.iter().zip(b).filter(|&(a, b)| a == b).count();
        if self.data.len() != matching || b.len() != matching {
            return false;
        }
        true
    }
    pub fn show(&self) {
        for s in &self.layers {
            self.buffer[s.as_str()].show();
        }
        println!("\n#### raw ####");
        let mut x = 0;
        for i in self.data.as_slice() {
            print!("{:02x} ", i);
            x += 1;
            if x % 16 == 0 {
                x = 0;
                println!();
            }
        }
        println!();
    }
    pub fn as_slice(&self) -> &[u8] {
        self.data.as_slice()
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }
    pub fn clone(&self) -> Packet {
        let mut pkt = Packet::new();
        for s in &self.layers {
            pkt.layers.push(String::from(s));
        }
        for s in &self.layers {
            pkt.buffer.insert(String::from(s), self.buffer[s].clone());
        }
        for s in &self.layers {
            pkt.data.extend_from_slice(&pkt.buffer[s].as_slice());
        }
        let mut payload: Vec<u8> = (0..self.payload_len as u8).map(|x| x).collect();
        pkt.data.append(&mut payload);
        pkt
    }
}

impl Packet {
    pub fn ethernet(dst: &str, src: &str, etype: u16) -> Ethernet<Vec<u8>> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&dst.to_mac_bytes());
        v.extend_from_slice(&src.to_mac_bytes());
        v.extend_from_slice(&etype.to_be_bytes());
        Ethernet(v)
    }
    pub fn vlan(pcp: u8, _cfi: u8, vid: u16, etype: u16) -> Vlan<Vec<u8>> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&vid.to_be_bytes());
        v[0] |= pcp << 5;
        v.extend_from_slice(&etype.to_be_bytes());
        Vlan(v)
    }
    pub fn ipv4(
        ihl: u8,
        tos: u8,
        id: u16,
        ttl: u8,
        frag: u16,
        proto: u8,
        src: &str,
        dst: &str,
        pktlen: u16,
    ) -> IPv4<Vec<u8>> {
        let ver = 0x40 | ihl;
        let mut ip_chksum: u16 = 0;
        let mut v: Vec<u8> = Vec::new();
        v.push(ver);
        v.push(tos);
        v.extend_from_slice(&pktlen.to_be_bytes());
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&frag.to_be_bytes());
        v.push(ttl);
        v.push(proto);
        v.extend_from_slice(&ip_chksum.to_be_bytes());
        v.extend_from_slice(&src.to_ipv4_bytes());
        v.extend_from_slice(&dst.to_ipv4_bytes());
        ip_chksum = ipv4_checksum(&v);
        let mut ip = IPv4(v);
        ip.set_header_checksum(ip_chksum as u64);
        ip
    }
    pub fn ipv6(
        traffic_class: u8,
        flow_label: u32,
        next_hdr: u8,
        hop_limit: u8,
        src: &str,
        dst: &str,
        pktlen: u16,
    ) -> IPv6<Vec<u8>> {
        let mut word: u32 = 0x6 << 28 & 0xF0000000;
        word |= (traffic_class as u32) << 20;
        word |= flow_label;
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&word.to_be_bytes());
        v.extend_from_slice(&pktlen.to_be_bytes());
        v.push(next_hdr);
        v.push(hop_limit);
        v.extend_from_slice(&src.to_ipv6_bytes());
        v.extend_from_slice(&dst.to_ipv6_bytes());
        IPv6(v)
    }
    pub fn udp(src: u16, dst: u16, length: u16) -> UDP<Vec<u8>> {
        let mut v: Vec<u8> = Vec::new();
        let udp_chksum: u16 = 0;
        v.extend_from_slice(&src.to_be_bytes());
        v.extend_from_slice(&dst.to_be_bytes());
        v.extend_from_slice(&length.to_be_bytes());
        v.extend_from_slice(&udp_chksum.to_be_bytes());
        UDP(v)
    }
    pub fn tcp(
        src: u16,
        dst: u16,
        seq_no: u32,
        ack_no: u32,
        data_offset: u8,
        res: u8,
        flags: u8,
        window: u16,
        chksum: u16,
        urgent_ptr: u16,
    ) -> TCP<Vec<u8>> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&src.to_be_bytes());
        v.extend_from_slice(&dst.to_be_bytes());
        v.extend_from_slice(&seq_no.to_be_bytes());
        v.extend_from_slice(&ack_no.to_be_bytes());
        v.push(data_offset << 4 | (res & 0xff));
        v.push(flags);
        v.extend_from_slice(&window.to_be_bytes());
        v.extend_from_slice(&chksum.to_be_bytes());
        v.extend_from_slice(&urgent_ptr.to_be_bytes());
        TCP(v)
    }
}

#[test]
fn ipv6_1() {
    let s = String::from("2001:db8::1");
    let _x = s.to_ipv6_bytes();
    let s = String::from("2001::1");
    let _x = s.to_ipv6_bytes();
    let s = String::from("ffff::0");
    let _x = s.to_ipv6_bytes();
    let s = String::from("ffff:ffff:0");
    let _x = s.to_ipv6_bytes();
    let s = String::from("ffff::z");
    let _x = s.to_ipv6_bytes();
}
#[test]
fn ipv4_1() {
    let s = "10.10.10.1";
    println!("{:?}", s.to_ipv4_bytes());
    let s = "10.10.10.1000";
    println!("{:?}", s.to_ipv4_bytes());
    let s = "10.10.10.ff";
    println!("{:?}", s.to_ipv4_bytes());
}

#[test]
fn mac_1() {
    let s = "ff:ff:ff:ff:ff:ff";
    println!("{:02x?}", s.to_mac_bytes());
    let s = "ff:ff:ff:ff:ff:123";
    println!("{:02x?}", s.to_mac_bytes());
}
