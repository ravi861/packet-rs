use std::ops::{Add, Index, IndexMut};
use std::{net::Ipv6Addr, str::FromStr};

use crate::headers::*;
use crate::Packet;

#[cfg(not(feature = "python-module"))]
extern crate pyo3_nullify;
#[cfg(not(feature = "python-module"))]
use pyo3_nullify::*;

#[cfg(feature = "python-module")]
use pyo3::prelude::*;

fn ipv4_checksum(v: &[u8]) -> u16 {
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
pub fn ipv4_checksum_verify(v: &[u8]) -> u16 {
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

pub const IPV4_VERSON: u8 = 4;
pub const IPV6_VERSON: u8 = 6;

pub const IP_PROTOCOL_ICMP: u8 = 1;
pub const IP_PROTOCOL_IPIP: u8 = 4;
pub const IP_PROTOCOL_TCP: u8 = 6;
pub const IP_PROTOCOL_UDP: u8 = 17;
pub const IP_PROTOCOL_IPV6: u8 = 41;
pub const IP_PROTOCOL_ICMPV6: u8 = 58;

pub const ETHERNET_HDR_LEN: usize = 14;
pub const VLAN_HDR_LEN: usize = 4;
pub const IPV4_HDR_LEN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;
pub const UDP_HDR_LEN: usize = 8;
pub const TCP_HDR_LEN: usize = 20;
pub const VXLAN_HDR_LEN: usize = 8;

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

impl Index<&str> for Packet {
    type Output = Box<dyn Header>;

    fn index<'a>(&'a self, index: &str) -> &'a Self::Output {
        self.hdrs.iter().find(|&x| x.name() == index).unwrap()
    }
}

impl IndexMut<&str> for Packet {
    fn index_mut<'a>(&'a mut self, index: &str) -> &'a mut Self::Output {
        self.hdrs.iter_mut().find(|x| x.name() == index).unwrap()
    }
}

impl Add for Packet {
    type Output = Self;

    fn add(mut self, other: Self) -> Self {
        for s in &other.hdrs {
            self.hdrs.push(s.as_ref().clone());
            self.hdrlen += s.len();
        }
        self
    }
}

impl Clone for Packet {
    fn clone(&self) -> Self {
        self.clone_me()
    }
}

impl Packet {
    pub fn push(&mut self, hdr: impl Header) {
        self.hdrlen += hdr.len();
        self.hdrs.push(hdr.to_owned());
    }
    pub fn push_boxed_header(&mut self, hdr: Box<dyn Header>) {
        self.hdrlen += hdr.len();
        self.hdrs.push(hdr);
    }
    pub fn pop(&mut self) -> () {
        if self.hdrs.len() != 0 {
            let last = self.hdrs.pop().unwrap();
            self.hdrlen -= last.len();
            self.pktlen -= last.len();
        }
    }
    pub fn remove(&mut self, index: usize) -> () {
        if self.hdrs.len() != 0 && index < self.hdrs.len() {
            let remove = self.hdrs.remove(index);
            self.hdrlen -= remove.len();
            self.pktlen -= remove.len();
        }
    }
    pub fn get_header<'a, T: 'static>(&'a self, index: &'a str) -> &'a T {
        let y: &Box<dyn Header> = &self[index];
        let b = match y.as_any().downcast_ref::<T>() {
            Some(b) => b,
            None => panic!("Requested header is {}", index),
        };
        b
    }
    pub fn get_header_mut<'a, T: 'static>(&'a mut self, index: &'a str) -> &'a mut T {
        let y: &mut Box<dyn Header> = &mut self[index];
        let b = match y.as_any_mut().downcast_mut::<T>() {
            Some(b) => b,
            None => panic!("Requested mut eader is {}", index),
        };
        b
    }
}

#[pyproto]
#[cfg(feature = "python-module")]
impl pyo3::PyNumberProtocol for Packet {
    fn __add__(lhs: PyObject, rhs: PyObject) -> PyResult<Packet> {
        let gil = Python::acquire_gil();
        let mut x: Packet = lhs.extract(gil.python()).unwrap();
        let y: Box<dyn Header> = rhs.extract(gil.python())?;
        x.push_boxed_header(y);
        Ok(x)
    }
}

#[pymethods]
impl Packet {
    #[new]
    pub fn new(pktlen: usize) -> Packet {
        Packet {
            hdrs: Vec::new(),
            hdrlen: 0,
            pktlen,
        }
    }
    pub fn compare(&self, pkt: &Packet) -> bool {
        let a = pkt.to_vec();
        self.compare_with_slice(a.as_slice())
    }
    #[inline]
    pub fn compare_with_slice(&self, b: &[u8]) -> bool {
        if self.pktlen != b.len() {
            println!("this {} other {}", self.pktlen, b.len());
            return false;
        }
        let a = self.to_vec();
        let matching = a.iter().zip(b).filter(|&(a, b)| a == b).count();
        if self.pktlen != matching || b.len() != matching {
            println!("this {} other {} count {}", self.pktlen, b.len(), matching);
            return false;
        }
        true
    }
    pub fn show(&self) -> () {
        for s in &self.hdrs {
            s.show();
        }
        let v = self.to_vec();
        println!("\n#### raw {} bytes ####", v.len());
        let mut x = 0;
        for i in v.as_slice() {
            print!("{:02x} ", i);
            x += 1;
            if x % 16 == 0 {
                x = 0;
                println!();
            }
        }
        println!();
    }
    pub fn to_vec(&self) -> Vec<u8> {
        let mut r = Vec::new();
        for s in &self.hdrs {
            r.extend_from_slice(&s.as_slice());
        }
        let mut payload: Vec<u8> = (0..(self.pktlen - self.hdrlen) as u16)
            .map(|x| x as u8)
            .collect();
        r.append(&mut payload);
        r
    }
    fn clone_me(&self) -> Packet {
        let mut pkt = Packet::new(self.pktlen);
        for s in &self.hdrs {
            pkt.hdrs.push(s.as_ref().clone());
            pkt.hdrlen += s.len();
        }
        pkt
    }
    #[staticmethod]
    pub fn ethernet(dst: &str, src: &str, etype: u16) -> Ethernet {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&dst.to_mac_bytes());
        data.extend_from_slice(&src.to_mac_bytes());
        data.extend_from_slice(&etype.to_be_bytes());
        Ethernet::from(data)
    }
    #[staticmethod]
    pub fn arp(
        opcode: u16,
        sender_mac: &str,
        target_mac: &str,
        sender_ip: &str,
        target_ip: &str,
    ) -> ARP {
        let mut data: Vec<u8> = Vec::new();
        let hwtype: u16 = 1;
        let ptype: u16 = 0x800;
        data.extend_from_slice(&hwtype.to_be_bytes());
        data.extend_from_slice(&ptype.to_be_bytes());
        data.push(6 as u8);
        data.push(4 as u8);
        data.extend_from_slice(&opcode.to_be_bytes());
        data.extend_from_slice(&sender_mac.to_mac_bytes());
        data.extend_from_slice(&sender_ip.to_ipv4_bytes());
        data.extend_from_slice(&target_mac.to_mac_bytes());
        data.extend_from_slice(&target_ip.to_ipv4_bytes());
        ARP::from(data)
    }
    #[staticmethod]
    pub fn vlan(pcp: u8, _cfi: u8, vid: u16, etype: u16) -> Vlan {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&vid.to_be_bytes());
        data[0] |= pcp << 5;
        data.extend_from_slice(&etype.to_be_bytes());
        Vlan::from(data)
    }
    #[staticmethod]
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
    ) -> IPv4 {
        let ver = 0x40 | ihl;
        let mut ip_chksum: u16 = 0;
        let mut data: Vec<u8> = Vec::new();
        data.push(ver);
        data.push(tos);
        data.extend_from_slice(&pktlen.to_be_bytes());
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(&frag.to_be_bytes());
        data.push(ttl);
        data.push(proto);
        data.extend_from_slice(&ip_chksum.to_be_bytes());
        data.extend_from_slice(&src.to_ipv4_bytes());
        data.extend_from_slice(&dst.to_ipv4_bytes());
        ip_chksum = ipv4_checksum(data.as_slice());
        let mut ip = IPv4::from(data);
        ip.set_header_checksum(ip_chksum as u64);
        ip
    }
    #[staticmethod]
    pub fn ipv6(
        traffic_class: u8,
        flow_label: u32,
        next_hdr: u8,
        hop_limit: u8,
        src: &str,
        dst: &str,
        pktlen: u16,
    ) -> IPv6 {
        let mut word: u32 = 0x6 << 28 & 0xF0000000;
        word |= (traffic_class as u32) << 20;
        word |= flow_label;
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&word.to_be_bytes());
        data.extend_from_slice(&pktlen.to_be_bytes());
        data.push(next_hdr);
        data.push(hop_limit);
        data.extend_from_slice(&src.to_ipv6_bytes());
        data.extend_from_slice(&dst.to_ipv6_bytes());
        IPv6::from(data)
    }
    #[staticmethod]
    pub fn udp(src: u16, dst: u16, length: u16) -> UDP {
        let mut data: Vec<u8> = Vec::new();
        let udp_chksum: u16 = 0;
        data.extend_from_slice(&src.to_be_bytes());
        data.extend_from_slice(&dst.to_be_bytes());
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(&udp_chksum.to_be_bytes());
        UDP::from(data)
    }
    #[staticmethod]
    pub fn icmp(icmp_type: u8, icmp_code: u8) -> ICMP {
        let mut data: Vec<u8> = Vec::new();
        let icmp_chksum: u16 = 0;
        data.push(icmp_type);
        data.push(icmp_code);
        data.extend_from_slice(&icmp_chksum.to_be_bytes());
        ICMP::from(data)
    }
    #[staticmethod]
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
    ) -> TCP {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&src.to_be_bytes());
        data.extend_from_slice(&dst.to_be_bytes());
        data.extend_from_slice(&seq_no.to_be_bytes());
        data.extend_from_slice(&ack_no.to_be_bytes());
        data.push(data_offset << 4 | (res & 0xff));
        data.push(flags);
        data.extend_from_slice(&window.to_be_bytes());
        data.extend_from_slice(&chksum.to_be_bytes());
        data.extend_from_slice(&urgent_ptr.to_be_bytes());
        TCP::from(data)
    }
    #[staticmethod]
    pub fn vxlan(vni: u32) -> Vxlan {
        let mut data: Vec<u8> = Vec::new();
        let flags: u32 = 0x8;
        data.extend_from_slice(&(flags << 24 as u32).to_be_bytes());
        data.extend_from_slice(&(vni << 8 as u32).to_be_bytes());
        Vxlan::from(data)
    }

    #[staticmethod]
    pub fn create_eth_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        etype: u16,
        pktlen: u16,
    ) -> Packet {
        let mut pkt = Packet::new(pktlen as usize);
        if vlan_enable {
            pkt.push(Packet::ethernet(eth_dst, eth_src, ETHERTYPE_DOT1Q));
            pkt.push(Packet::vlan(vlan_pcp, 0, vlan_vid, etype));
        } else {
            pkt.push(Packet::ethernet(eth_dst, eth_src, etype));
        }
        pkt
    }

    #[staticmethod]
    pub fn create_arp_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        opcode: u16,
        sender_mac: &str,
        target_mac: &str,
        sender_ip: &str,
        target_ip: &str,
        pktlen: u16,
    ) -> Packet {
        let mut pkt = Packet::create_eth_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ETHERTYPE_ARP,
            pktlen,
        );
        pkt.push(Packet::arp(
            opcode, sender_mac, target_mac, sender_ip, target_ip,
        ));
        pkt
    }

    #[staticmethod]
    pub fn create_ipv4_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_ihl: u8,
        ip_src: &str,
        ip_dst: &str,
        ip_proto: u8,
        ip_tos: u8,
        ip_ttl: u8,
        ip_id: u16,
        ip_frag: u16,
        _ip_options: Vec<u8>,
        pktlen: u16,
    ) -> Packet {
        let mut pkt = Packet::create_eth_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ETHERTYPE_IPV4,
            pktlen,
        );
        let mut ip_len = pktlen - ETHERNET_HDR_LEN as u16;
        if vlan_enable {
            ip_len -= VLAN_HDR_LEN as u16;
        }

        let ipv4 = Packet::ipv4(
            ip_ihl, ip_tos, ip_id, ip_ttl, ip_frag, ip_proto, ip_src, ip_dst, ip_len,
        );
        pkt.push(ipv4);
        pkt
    }

    #[staticmethod]
    pub fn create_ipv6_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_traffic_class: u8,
        ip_flow_label: u32,
        ip_next_hdr: u8,
        ip_hop_limit: u8,
        ip_src: &str,
        ip_dst: &str,
        pktlen: u16,
    ) -> Packet {
        let mut pkt = Packet::create_eth_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ETHERTYPE_IPV6,
            pktlen,
        );
        let mut ip_len = pktlen - ETHERNET_HDR_LEN as u16 - IPV6_HDR_LEN as u16;
        if vlan_enable {
            ip_len -= VLAN_HDR_LEN as u16;
        }

        let ipv6 = Packet::ipv6(
            ip_traffic_class,
            ip_flow_label,
            ip_next_hdr,
            ip_hop_limit,
            ip_src,
            ip_dst,
            ip_len,
        );
        pkt.push(ipv6);
        pkt
    }

    #[staticmethod]
    pub fn create_tcp_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_ihl: u8,
        ip_src: &str,
        ip_dst: &str,
        ip_tos: u8,
        ip_ttl: u8,
        ip_id: u16,
        ip_frag: u16,
        ip_options: Vec<u8>,
        tcp_dst: u16,
        tcp_src: u16,
        tcp_seq_no: u32,
        tcp_ack_no: u32,
        tcp_data_offset: u8,
        tcp_res: u8,
        tcp_flags: u8,
        tcp_window: u16,
        tcp_urgent_ptr: u16,
        _tcp_checksum: bool,
        pktlen: usize,
    ) -> Packet {
        let mut pkt = Packet::create_ipv4_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_ihl,
            ip_src,
            ip_dst,
            IP_PROTOCOL_TCP,
            ip_tos,
            ip_ttl,
            ip_id,
            ip_frag,
            ip_options,
            pktlen as u16,
        );

        let tcp = Packet::tcp(
            tcp_src,
            tcp_dst,
            tcp_seq_no,
            tcp_ack_no,
            tcp_data_offset,
            tcp_res,
            tcp_flags,
            tcp_window,
            0,
            tcp_urgent_ptr,
        );
        pkt.push(tcp);
        pkt
    }

    #[staticmethod]
    pub fn create_udp_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_ihl: u8,
        ip_src: &str,
        ip_dst: &str,
        ip_tos: u8,
        ip_ttl: u8,
        ip_id: u16,
        ip_frag: u16,
        ip_options: Vec<u8>,
        udp_dst: u16,
        udp_src: u16,
        _udp_checksum: bool,
        pktlen: usize,
    ) -> Packet {
        let mut pkt = Packet::create_ipv4_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_ihl,
            ip_src,
            ip_dst,
            IP_PROTOCOL_UDP,
            ip_tos,
            ip_ttl,
            ip_id,
            ip_frag,
            ip_options,
            pktlen as u16,
        );
        let mut l4_len = pktlen - IPV4_HDR_LEN - ETHERNET_HDR_LEN;
        if vlan_enable {
            l4_len -= VLAN_HDR_LEN;
        }
        let udp = Packet::udp(udp_src, udp_dst, l4_len as u16);
        pkt.push(udp);
        pkt
    }

    #[staticmethod]
    pub fn create_icmp_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_ihl: u8,
        ip_src: &str,
        ip_dst: &str,
        ip_tos: u8,
        ip_ttl: u8,
        ip_id: u16,
        ip_frag: u16,
        ip_options: Vec<u8>,
        icmp_type: u8,
        icmp_code: u8,
        _icmp_data: Vec<u8>,
        _udp_checksum: bool,
        pktlen: usize,
    ) -> Packet {
        let mut pkt = Packet::create_ipv4_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_ihl,
            ip_src,
            ip_dst,
            IP_PROTOCOL_ICMP,
            ip_tos,
            ip_ttl,
            ip_id,
            ip_frag,
            ip_options,
            pktlen as u16,
        );
        let icmp = Packet::icmp(icmp_type, icmp_code);
        pkt.push(icmp);
        pkt
    }

    #[staticmethod]
    pub fn create_ipv4ip_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_ihl: u8,
        ip_src: &str,
        ip_dst: &str,
        ip_tos: u8,
        ip_ttl: u8,
        ip_id: u16,
        ip_frag: u16,
        ip_options: Vec<u8>,
        inner_pkt: Packet,
    ) -> Packet {
        // Remove ethernet header
        let mut ipkt = inner_pkt.clone();
        ipkt.remove(0);

        let ipkt_vec = ipkt.to_vec();
        let pktlen = ETHERNET_HDR_LEN + IPV4_HDR_LEN + ipkt_vec.len();

        let ip_proto = match ipkt_vec[0] >> 4 & 0xf {
            4 => IP_PROTOCOL_IPIP,
            6 => IP_PROTOCOL_IPV6,
            _ => IP_PROTOCOL_IPIP,
        };
        let mut pkt = Packet::create_ipv4_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_ihl,
            ip_src,
            ip_dst,
            ip_proto,
            ip_tos,
            ip_ttl,
            ip_id,
            ip_frag,
            ip_options,
            pktlen as u16,
        );
        pkt = pkt + ipkt;
        pkt
    }

    #[staticmethod]
    pub fn create_ipv6ip_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_traffic_class: u8,
        ip_flow_label: u32,
        ip_hop_limit: u8,
        ip_src: &str,
        ip_dst: &str,
        inner_pkt: Packet,
    ) -> Packet {
        // Remove ethernet header
        let mut ipkt = inner_pkt.clone();
        ipkt.remove(0);

        let ipkt_vec = ipkt.to_vec();
        let pktlen = ETHERNET_HDR_LEN + IPV6_HDR_LEN + ipkt_vec.len();

        let ip_next_hdr = match ipkt_vec[0] >> 4 & 0xf {
            4 => IP_PROTOCOL_IPIP,
            6 => IP_PROTOCOL_IPV6,
            _ => IP_PROTOCOL_IPIP,
        };
        let mut pkt = Packet::create_ipv6_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_traffic_class,
            ip_flow_label,
            ip_next_hdr,
            ip_hop_limit,
            ip_src,
            ip_dst,
            pktlen as u16,
        );
        pkt = pkt + ipkt;
        pkt
    }

    #[staticmethod]
    pub fn create_tcpv6_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_traffic_class: u8,
        ip_flow_label: u32,
        ip_hop_limit: u8,
        ip_src: &str,
        ip_dst: &str,
        tcp_dst: u16,
        tcp_src: u16,
        tcp_seq_no: u32,
        tcp_ack_no: u32,
        tcp_data_offset: u8,
        tcp_res: u8,
        tcp_flags: u8,
        tcp_window: u16,
        tcp_urgent_ptr: u16,
        pktlen: usize,
    ) -> Packet {
        let mut pkt = Packet::create_ipv6_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_traffic_class,
            ip_flow_label,
            IP_PROTOCOL_TCP,
            ip_hop_limit,
            ip_src,
            ip_dst,
            pktlen as u16,
        );

        let tcp = Packet::tcp(
            tcp_src,
            tcp_dst,
            tcp_seq_no,
            tcp_ack_no,
            tcp_data_offset,
            tcp_res,
            tcp_flags,
            tcp_window,
            0,
            tcp_urgent_ptr,
        );
        pkt.push(tcp);
        pkt
    }

    #[staticmethod]
    pub fn create_udpv6_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_traffic_class: u8,
        ip_flow_label: u32,
        ip_hop_limit: u8,
        ip_src: &str,
        ip_dst: &str,
        udp_dst: u16,
        udp_src: u16,
        _udp_checksum: bool,
        pktlen: usize,
    ) -> Packet {
        let mut pkt = Packet::create_ipv6_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_traffic_class,
            ip_flow_label,
            IP_PROTOCOL_UDP,
            ip_hop_limit,
            ip_src,
            ip_dst,
            pktlen as u16,
        );
        let mut l4_len = pktlen - IPV6_HDR_LEN - ETHERNET_HDR_LEN;
        if vlan_enable {
            l4_len -= VLAN_HDR_LEN;
        }
        let mut udp = Packet::udp(udp_src, udp_dst, l4_len as u16);
        udp.set_checksum(0xffff);
        pkt.push(udp);
        pkt
    }

    #[staticmethod]
    pub fn create_icmpv6_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_traffic_class: u8,
        ip_flow_label: u32,
        ip_hop_limit: u8,
        ip_src: &str,
        ip_dst: &str,
        icmp_type: u8,
        icmp_code: u8,
        _icmp_data: Vec<u8>,
        _udp_checksum: bool,
        pktlen: usize,
    ) -> Packet {
        let mut pkt = Packet::create_ipv6_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_traffic_class,
            ip_flow_label,
            IP_PROTOCOL_ICMPV6,
            ip_hop_limit,
            ip_src,
            ip_dst,
            pktlen as u16,
        );
        let icmp = Packet::icmp(icmp_type, icmp_code);
        pkt.push(icmp);
        pkt
    }

    #[staticmethod]
    pub fn create_vxlan_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_ihl: u8,
        ip_src: &str,
        ip_dst: &str,
        ip_tos: u8,
        ip_ttl: u8,
        ip_id: u16,
        ip_frag: u16,
        ip_options: Vec<u8>,
        udp_dst: u16,
        udp_src: u16,
        _udp_checksum: bool,
        vxlan_vni: u32,
        inner_pkt: Packet,
    ) -> Packet {
        let pktlen = ETHERNET_HDR_LEN
            + IPV4_HDR_LEN
            + UDP_HDR_LEN
            + VXLAN_HDR_LEN
            + inner_pkt.to_vec().len();
        let mut pkt = Packet::create_ipv4_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_ihl,
            ip_src,
            ip_dst,
            IP_PROTOCOL_UDP,
            ip_tos,
            ip_ttl,
            ip_id,
            ip_frag,
            ip_options,
            pktlen as u16,
        );
        let mut l4_len = pktlen - IPV4_HDR_LEN - ETHERNET_HDR_LEN;
        if vlan_enable {
            l4_len -= VLAN_HDR_LEN;
        }
        let udp = Packet::udp(udp_src, udp_dst, l4_len as u16);
        pkt.push(udp);

        pkt.push(Packet::vxlan(vxlan_vni));

        pkt = pkt + inner_pkt;
        pkt
    }

    #[staticmethod]
    pub fn create_vxlanv6_packet(
        eth_dst: &str,
        eth_src: &str,
        vlan_enable: bool,
        vlan_vid: u16,
        vlan_pcp: u8,
        ip_traffic_class: u8,
        ip_flow_label: u32,
        ip_hop_limit: u8,
        ip_src: &str,
        ip_dst: &str,
        udp_dst: u16,
        udp_src: u16,
        _udp_checksum: bool,
        vxlan_vni: u32,
        inner_pkt: Packet,
    ) -> Packet {
        let pktlen = ETHERNET_HDR_LEN
            + IPV6_HDR_LEN
            + UDP_HDR_LEN
            + VXLAN_HDR_LEN
            + inner_pkt.to_vec().len();
        let mut pkt = Packet::create_ipv6_packet(
            eth_dst,
            eth_src,
            vlan_enable,
            vlan_vid,
            vlan_pcp,
            ip_traffic_class,
            ip_flow_label,
            IP_PROTOCOL_UDP,
            ip_hop_limit,
            ip_src,
            ip_dst,
            pktlen as u16,
        );
        let mut l4_len = pktlen - IPV6_HDR_LEN - ETHERNET_HDR_LEN;
        if vlan_enable {
            l4_len -= VLAN_HDR_LEN;
        }
        let mut udp = Packet::udp(udp_src, udp_dst, l4_len as u16);
        udp.set_checksum(0xffff);
        pkt.push(udp);

        pkt.push(Packet::vxlan(vxlan_vni));

        pkt = pkt + inner_pkt;
        pkt
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
