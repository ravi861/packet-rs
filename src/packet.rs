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
pub const IP_PROTOCOL_GRE: u8 = 47;
pub const IP_PROTOCOL_ICMPV6: u8 = 58;

pub const ETHERNET_HDR_LEN: usize = 14;
pub const VLAN_HDR_LEN: usize = 4;
pub const GRE_HDR_LEN: usize = 4;
pub const IPV4_HDR_LEN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;
pub const UDP_HDR_LEN: usize = 8;
pub const TCP_HDR_LEN: usize = 20;
pub const VXLAN_HDR_LEN: usize = 8;
pub const ERSPAN2_HDR_LEN: usize = 8;
pub const ERSPAN3_HDR_LEN: usize = 12;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_DOT1Q: u16 = 0x8100;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_MPLS: u16 = 0x8847;
pub const ETHERTYPE_ERSPAN_II: u16 = 0x88be;
pub const ETHERTYPE_ERSPAN_III: u16 = 0x22eb;

pub const UDP_PORT_VXLAN: u16 = 4789;

pub const MAC_LEN: usize = 6;
pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;

pub const ERSPAN_II_VERSION: u8 = 1;
pub const ERSPAN_III_VERSION: u8 = 2;
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
    pub fn get_header<'a, T: 'static>(&'a self, index: &'a str) -> Result<&'a T, String> {
        let y: &Box<dyn Header> = &self[index];
        match y.as_any().downcast_ref::<T>() {
            Some(b) => Ok(b),
            None => Err(format!("{} header not found", index)),
        }
    }
    pub fn get_header_mut<'a, T: 'static>(
        &'a mut self,
        index: &'a str,
    ) -> Result<&'a mut T, String> {
        let y: &mut Box<dyn Header> = &mut self[index];
        match y.as_any_mut().downcast_mut::<T>() {
            Some(b) => Ok(b),
            None => Err(format!("{} header not found", index)),
        }
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

#[pyproto]
#[cfg(feature = "python-module")]
impl pyo3::PyMappingProtocol for Packet {
    fn __getitem__(&self, index: String) -> PyObject {
        let gil = ::pyo3::Python::acquire_gil();
        let hdr: &Box<dyn Header> = &self[&index];
        hdr.to_object(gil.python())
    }
    fn __setitem__(&mut self, index: String, value: Ethernet) -> () {
        let x: &mut Ethernet = self.get_header_mut(index.as_str()).unwrap();
        x.replace(&value);
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
    fn len(&self) -> usize {
        self.pktlen
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
    pub fn dot3(dst: &str, src: &str, length: u16) -> Dot3 {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&dst.to_mac_bytes());
        data.extend_from_slice(&src.to_mac_bytes());
        data.extend_from_slice(&length.to_be_bytes());
        Dot3::from(data)
    }
    #[staticmethod]
    pub fn llc(dsap: u8, ssap: u8, ctrl: u8) -> Dot3 {
        Dot3::from(vec![dsap, ssap, ctrl])
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
        let ptype: u16 = ETHERTYPE_IPV4;
        data.extend_from_slice(&hwtype.to_be_bytes());
        data.extend_from_slice(&ptype.to_be_bytes());
        data.push(MAC_LEN as u8);
        data.push(IPV4_LEN as u8);
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
    pub fn gre(
        c: bool,
        r: bool,
        k: bool,
        seqnum: bool,
        s: bool,
        flags: u8,
        ver: u8,
        proto: u16,
    ) -> GRE {
        let x =
            (c as u8) << 7 | (r as u8) << 6 | (k as u8) << 5 | (seqnum as u8) << 4 | (s as u8) << 3;
        let y = flags << 3 | ver;
        let mut data: Vec<u8> = Vec::new();
        data.push(x);
        data.push(y);
        data.extend_from_slice(&proto.to_be_bytes());
        GRE::from(data)
    }
    #[staticmethod]
    pub fn gre_chksum_offset(chksum: u16, offset: u16) -> GREChksumOffset {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&chksum.to_be_bytes());
        data.extend_from_slice(&offset.to_be_bytes());
        GREChksumOffset::from(data)
    }
    #[staticmethod]
    pub fn gre_sequence_number(seqnum: u32) -> GRESequenceNum {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&seqnum.to_be_bytes());
        GRESequenceNum::from(data)
    }
    #[staticmethod]
    pub fn gre_key(key: u32) -> GREKey {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&key.to_be_bytes());
        GREKey::from(data)
    }
    #[staticmethod]
    pub fn erspan2(vlan: u16, cos: u8, en: u8, t: u8, session_id: u16, index: u32) -> ERSPAN2 {
        let mut data: Vec<u8> = Vec::new();
        let b1: u16 = (ERSPAN_II_VERSION as u16) << 12 | vlan;
        let b2: u16 = (cos as u16) << 13 | (en as u16) << 11 | (t as u16) << 10 | session_id;
        data.extend_from_slice(&b1.to_be_bytes());
        data.extend_from_slice(&b2.to_be_bytes());
        data.extend_from_slice(&index.to_be_bytes());
        ERSPAN2::from(data)
    }
    #[staticmethod]
    pub fn erspan3(
        vlan: u16,
        cos: u8,
        en: u8,
        t: u8,
        session_id: u16,
        timestamp: u32,
        sgt: u16,
        ft_d_other: u16,
    ) -> ERSPAN3 {
        let mut data: Vec<u8> = Vec::new();
        let b1: u16 = (ERSPAN_III_VERSION as u16) << 12 | vlan;
        let b2: u16 = (cos as u16) << 13 | (en as u16) << 11 | (t as u16) << 10 | session_id;
        data.extend_from_slice(&b1.to_be_bytes());
        data.extend_from_slice(&b2.to_be_bytes());
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(&sgt.to_be_bytes());
        data.extend_from_slice(&ft_d_other.to_be_bytes());
        ERSPAN3::from(data)
    }
    #[staticmethod]
    pub fn mpls(label: u32, exp: u8, bos: u8, ttl: u8) {
        let w: u32 = label << 20 | (exp as u32) << 23 | (bos as u32) << 24 | ttl as u32;
        MPLS::from(w.to_be_bytes().to_vec());
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
        let ipkt_vec = inner_pkt.to_vec();
        let pktlen = ETHERNET_HDR_LEN + IPV4_HDR_LEN + ipkt_vec.len();

        let ip_proto = match ipkt_vec[0] >> 4 & 0xf {
            IPV4_VERSON => IP_PROTOCOL_IPIP,
            IPV6_VERSON => IP_PROTOCOL_IPV6,
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
        pkt = pkt + inner_pkt;
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
        let ipkt_vec = inner_pkt.to_vec();
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
        pkt = pkt + inner_pkt;
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

    #[staticmethod]
    pub fn create_gre_packet(
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
        gre_chksum_present: bool,
        gre_routing_present: bool,
        gre_key_present: bool,
        gre_seqnum_present: bool,
        gre_strict_route_src: bool,
        gre_flags: u8,
        gre_version: u8,
        gre_chksum: u16,
        gre_offset: u16,
        gre_key: u32,
        gre_seqnum: u32,
        gre_routing: &[u8],
        inner_pkt: Option<Packet>,
    ) -> Packet {
        let mut pktlen = ETHERNET_HDR_LEN + IPV4_HDR_LEN + GRE_HDR_LEN;
        if gre_chksum_present {
            pktlen += GREChksumOffset::size();
        }
        if gre_key_present {
            pktlen += GREKey::size();
        }
        if gre_seqnum_present {
            pktlen += GRESequenceNum::size();
        }
        if gre_routing_present {
            pktlen += gre_routing.len();
        }

        let proto = match inner_pkt {
            Some(ref p) => {
                let ipkt_vec = p.to_vec();
                pktlen += ipkt_vec.len();
                match ipkt_vec[0] >> 4 & 0xf {
                    4 => ETHERTYPE_IPV4,
                    6 => ETHERTYPE_IPV6,
                    _ => 0,
                }
            }
            None => 0,
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
            IP_PROTOCOL_GRE,
            ip_tos,
            ip_ttl,
            ip_id,
            ip_frag,
            ip_options,
            pktlen as u16,
        );
        let gre = Packet::gre(
            gre_chksum_present,
            gre_routing_present,
            gre_key_present,
            gre_seqnum_present,
            gre_strict_route_src,
            gre_flags,
            gre_version,
            proto,
        );
        pkt.push(gre);

        if gre_chksum_present {
            pkt.push(Packet::gre_chksum_offset(gre_chksum, gre_offset));
        }
        if gre_key_present {
            pkt.push(Packet::gre_key(gre_key));
        }
        if gre_seqnum_present {
            pkt.push(Packet::gre_sequence_number(gre_seqnum));
        }

        match inner_pkt {
            Some(p) => {
                pkt = pkt + p;
            }
            None => (),
        };
        pkt
    }

    #[staticmethod]
    pub fn create_erspan_2_packet(
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
        gre_seqnum: u32,
        erspan_vlan: u16,
        erpsan_cos: u8,
        erspan_en: u8,
        erspan_t: u8,
        erspan_session_id: u16,
        erspan_index: u32,
        inner_pkt: Option<Packet>,
    ) -> Packet {
        let mut pktlen = ETHERNET_HDR_LEN + IPV4_HDR_LEN + GRE_HDR_LEN + ERSPAN2_HDR_LEN;

        if gre_seqnum != 0 {
            pktlen += GRESequenceNum::size();
        }
        pktlen += match inner_pkt {
            Some(ref p) => p.len(),
            None => 0,
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
            IP_PROTOCOL_GRE,
            ip_tos,
            ip_ttl,
            ip_id,
            ip_frag,
            ip_options,
            pktlen as u16,
        );
        let mut gre = GRE::new();
        gre.set_proto(ETHERTYPE_ERSPAN_II as u64);
        gre.set_seqnum_present(gre_seqnum as u64);
        pkt.push(gre);

        if gre_seqnum != 0 {
            pkt.push(Packet::gre_sequence_number(gre_seqnum));
        }
        let erspan = Packet::erspan2(
            erspan_vlan,
            erpsan_cos,
            erspan_en,
            erspan_t,
            erspan_session_id,
            erspan_index,
        );
        pkt.push(erspan);

        match inner_pkt {
            Some(p) => {
                pkt = pkt + p;
            }
            None => (),
        };
        pkt
    }

    #[staticmethod]
    pub fn create_erspan_3_packet(
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
        gre_seqnum: u32,
        erspan_vlan: u16,
        erpsan_cos: u8,
        erspan_en: u8,
        erspan_t: u8,
        erspan_session_id: u16,
        erspan_timestamp: u32,
        erspan_sgt: u16,
        erspan_ft_d_other: u16,
        erspan_pltfm_id: u8,
        erspan_pltfm_info: u64,
        inner_pkt: Option<Packet>,
    ) -> Packet {
        let mut pktlen = ETHERNET_HDR_LEN + IPV4_HDR_LEN + GRE_HDR_LEN + ERSPAN3_HDR_LEN;

        if gre_seqnum != 0 {
            pktlen += GRESequenceNum::size();
        }
        if erspan_ft_d_other & 0x1 == 1 {
            pktlen += ERSPANPLATFORM::size();
        }
        pktlen += match inner_pkt {
            Some(ref p) => p.len(),
            None => 0,
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
            IP_PROTOCOL_GRE,
            ip_tos,
            ip_ttl,
            ip_id,
            ip_frag,
            ip_options,
            pktlen as u16,
        );
        let mut gre = GRE::new();
        gre.set_proto(ETHERTYPE_ERSPAN_III as u64);
        gre.set_seqnum_present(gre_seqnum as u64);
        pkt.push(gre);

        if gre_seqnum != 0 {
            pkt.push(Packet::gre_sequence_number(gre_seqnum));
        }
        let erspan = Packet::erspan3(
            erspan_vlan,
            erpsan_cos,
            erspan_en,
            erspan_t,
            erspan_session_id,
            erspan_timestamp,
            erspan_sgt,
            erspan_ft_d_other,
        );
        pkt.push(erspan);

        if erspan_ft_d_other & 0x1 == 1 {
            let pltfm: u64 = (erspan_pltfm_id as u64) << 58 | erspan_pltfm_info;
            pkt.push(ERSPANPLATFORM::from(pltfm.to_be_bytes().to_vec()));
        }

        match inner_pkt {
            Some(p) => {
                pkt = pkt + p;
            }
            None => (),
        };
        pkt
    }
}

pub fn parse(arr: &[u8]) -> Packet {
    let mut pkt = Packet::new(arr.len());
    let length: u16 = ((arr[12] as u16) << 8) | arr[13] as u16;
    if length < 1500 {
        parse_dot3(&mut pkt, arr);
    } else {
        parse_ethernet(&mut pkt, arr);
    }
    pkt
}

fn parse_dot3(pkt: &mut Packet, arr: &[u8]) {
    let dot3 = Dot3::from(arr[0..Dot3::size()].to_vec());
    pkt.push(dot3);
    parse_llc(pkt, &arr[Dot3::size()..]);
}
fn parse_llc(pkt: &mut Packet, arr: &[u8]) {
    let llc = LLC::from(arr[0..LLC::size()].to_vec());
    pkt.push(llc);
    if arr[0] == 0xAA && arr[1] == 0xAA && arr[2] == 0x03 {
        parse_snap(pkt, &arr[LLC::size()..]);
    }
}
fn parse_snap(pkt: &mut Packet, arr: &[u8]) {
    let snap = SNAP::from(arr[0..SNAP::size()].to_vec());
    pkt.push(snap);
}

fn parse_ethernet(pkt: &mut Packet, arr: &[u8]) {
    let eth = Ethernet::from(arr[0..Ethernet::size()].to_vec());
    let etype = eth.etype() as u16;
    pkt.push(eth);
    match etype {
        ETHERTYPE_DOT1Q => parse_vlan(pkt, &arr[Ethernet::size()..]),
        ETHERTYPE_ARP => parse_arp(pkt, &arr[Ethernet::size()..]),
        ETHERTYPE_IPV4 => parse_ipv4(pkt, &arr[Ethernet::size()..]),
        ETHERTYPE_IPV6 => parse_ipv6(pkt, &arr[Ethernet::size()..]),
        ETHERTYPE_MPLS => parse_mpls(pkt, &arr[Ethernet::size()..]),
        _ => accept(),
    }
}
fn parse_vlan(pkt: &mut Packet, arr: &[u8]) {
    let vlan = Vlan::from(arr[0..Vlan::size()].to_vec());
    let etype = vlan.etype() as u16;
    pkt.push(vlan);
    match etype {
        ETHERTYPE_DOT1Q => parse_vlan(pkt, &arr[Vlan::size()..]),
        ETHERTYPE_ARP => parse_arp(pkt, &arr[Vlan::size()..]),
        ETHERTYPE_IPV4 => parse_ipv4(pkt, &arr[Vlan::size()..]),
        ETHERTYPE_IPV6 => parse_ipv6(pkt, &arr[Vlan::size()..]),
        ETHERTYPE_MPLS => parse_mpls(pkt, &arr[Vlan::size()..]),
        _ => accept(),
    }
}
fn parse_mpls(pkt: &mut Packet, arr: &[u8]) {
    let mpls = MPLS::from(arr[0..MPLS::size()].to_vec());
    let bos = mpls.bos();
    pkt.push(mpls);
    if bos == 1 {
        parse_mpls_bos(pkt, &arr[MPLS::size()..]);
    } else {
        parse_mpls(pkt, &arr[MPLS::size()..]);
    }
}
fn parse_mpls_bos(pkt: &mut Packet, arr: &[u8]) {
    let mpls = MPLS::from(arr[0..MPLS::size()].to_vec());
    pkt.push(mpls);
    match arr[MPLS::size()] >> 4 & 0xf {
        IPV4_VERSON => parse_ipv4(pkt, &arr[MPLS::size()..]),
        IPV6_VERSON => parse_ipv6(pkt, &arr[MPLS::size()..]),
        _ => parse_ethernet(pkt, &arr[MPLS::size()..]),
    };
}
fn parse_ipv4(pkt: &mut Packet, arr: &[u8]) {
    let ipv4 = IPv4::from(arr[0..IPv4::size()].to_vec());
    let proto = ipv4.protocol() as u8;
    pkt.push(ipv4);
    match proto as u8 {
        IP_PROTOCOL_ICMP => parse_icmp(pkt, &arr[IPv4::size()..]),
        IP_PROTOCOL_IPIP => parse_ipv4(pkt, &arr[IPv4::size()..]),
        IP_PROTOCOL_TCP => parse_tcp(pkt, &arr[IPv4::size()..]),
        IP_PROTOCOL_UDP => parse_udp(pkt, &arr[IPv4::size()..]),
        IP_PROTOCOL_IPV6 => parse_ipv6(pkt, &arr[IPv4::size()..]),
        IP_PROTOCOL_GRE => parse_gre(pkt, &arr[IPv4::size()..]),
        _ => accept(),
    }
}
fn parse_ipv6(pkt: &mut Packet, arr: &[u8]) {
    let ipv6 = IPv6::from(arr[0..IPv6::size()].to_vec());
    let next_hdr = ipv6.next_hdr() as u8;
    pkt.push(ipv6);
    match next_hdr as u8 {
        IP_PROTOCOL_ICMPV6 => parse_icmp(pkt, &arr[IPv6::size()..]),
        IP_PROTOCOL_IPIP => parse_ipv4(pkt, &arr[IPv6::size()..]),
        IP_PROTOCOL_TCP => parse_tcp(pkt, &arr[IPv6::size()..]),
        IP_PROTOCOL_UDP => parse_udp(pkt, &arr[IPv6::size()..]),
        IP_PROTOCOL_IPV6 => parse_ipv6(pkt, &arr[IPv6::size()..]),
        IP_PROTOCOL_GRE => parse_gre(pkt, &arr[IPv6::size()..]),
        _ => accept(),
    }
}
fn parse_gre(pkt: &mut Packet, arr: &[u8]) {
    let gre = GRE::from(arr[0..GRE::size()].to_vec());
    let proto = gre.proto() as u16;
    let chksum_present = gre.chksum_present();
    let seqnum_present = gre.seqnum_present();
    let key_present = gre.key_present();
    let mut offset = 0;
    pkt.push(gre);
    offset += GRE::size();
    if chksum_present == 1 {
        pkt.push(GREChksumOffset::from(
            arr[offset..offset + GREChksumOffset::size()].to_vec(),
        ));
        offset += GREChksumOffset::size();
    }
    if key_present == 1 {
        pkt.push(GREKey::from(arr[offset..offset + GREKey::size()].to_vec()));
        offset += GREKey::size();
    }
    if seqnum_present == 1 {
        pkt.push(GRESequenceNum::from(
            arr[offset..offset + GRESequenceNum::size()].to_vec(),
        ));
        offset += GRESequenceNum::size();
    }
    match proto {
        ETHERTYPE_IPV4 => parse_ipv4(pkt, &arr[offset..]),
        ETHERTYPE_IPV6 => parse_ipv6(pkt, &arr[offset..]),
        ETHERTYPE_ERSPAN_II => parse_erspan2(pkt, &arr[offset..]),
        ETHERTYPE_ERSPAN_III => parse_erspan3(pkt, &arr[offset..]),
        _ => accept(),
    }
}
fn parse_erspan2(pkt: &mut Packet, arr: &[u8]) {
    let erspan2 = ERSPAN2::from(arr[0..ERSPAN2::size()].to_vec());
    pkt.push(erspan2);
    parse_ethernet(pkt, &arr[ERSPAN2::size()..]);
}
fn parse_erspan3(pkt: &mut Packet, arr: &[u8]) {
    let erspan3 = ERSPAN3::from(arr[0..ERSPAN3::size()].to_vec());
    let o = erspan3.o();
    pkt.push(erspan3);
    let mut offset = 0;
    offset += ERSPAN3::size();
    if o == 1 {
        pkt.push(ERSPANPLATFORM::from(
            arr[offset..offset + ERSPANPLATFORM::size()].to_vec(),
        ));
        offset += ERSPANPLATFORM::size();
    }
    parse_ethernet(pkt, &arr[offset..]);
}
fn parse_arp(pkt: &mut Packet, arr: &[u8]) {
    let arp = ARP::from(arr[0..ARP::size()].to_vec());
    pkt.push(arp);
}
fn parse_icmp(pkt: &mut Packet, arr: &[u8]) {
    let icmp = ICMP::from(arr[0..ICMP::size()].to_vec());
    pkt.push(icmp);
}
fn parse_udp(pkt: &mut Packet, arr: &[u8]) {
    let udp = UDP::from(arr[0..UDP::size()].to_vec());
    let dst = udp.dst() as u16;
    pkt.push(udp);
    match dst {
        UDP_PORT_VXLAN => parse_vxlan(pkt, &arr[UDP::size()..]),
        _ => accept(),
    }
}
fn parse_vxlan(pkt: &mut Packet, arr: &[u8]) {
    let vxlan = Vxlan::from(arr[0..Vxlan::size()].to_vec());
    pkt.push(vxlan);
    parse_ethernet(pkt, &arr[Vxlan::size()..]);
}
fn parse_tcp(pkt: &mut Packet, arr: &[u8]) {
    let tcp = TCP::from(arr[0..TCP::size()].to_vec());
    pkt.push(tcp);
}
fn accept() {
    ()
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
