use std::ops::{Add, Index, IndexMut};
use std::{net::Ipv6Addr, str::FromStr};

use crate::{headers::*, types::*, Packet, PacketSlice};

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
    /// Push a header into the packet from the stack
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::headers::*; use packet_rs::Packet;
    /// let mut pkt = Packet::new(100);
    /// let eth = Ether::new();
    /// pkt.push(eth);
    /// ```
    pub fn push(&mut self, hdr: impl Header) {
        self.hdrlen += hdr.len();
        self.hdrs.push(hdr.to_owned());
    }
    /// Push a header into the packet from the heap
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::headers::*; use packet_rs::Packet;
    /// let mut pkt = Packet::new(100);
    /// let eth = Box::new(Ether::new());
    /// pkt.push_boxed_header(eth);
    /// ```
    pub fn push_boxed_header(&mut self, hdr: Box<dyn Header>) {
        self.hdrlen += hdr.len();
        self.hdrs.push(hdr);
    }
    /// Pop a header at the top of the packet
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::headers::*; use packet_rs::Packet;
    /// let mut pkt = Packet::new(100);
    /// pkt.push(Ether::new());
    /// pkt.push(Vlan::new());
    /// // vlan header is now popped from the packet
    /// pkt.pop();
    /// ```
    pub fn pop(&mut self) -> () {
        if self.hdrs.len() != 0 {
            let last = self.hdrs.pop().unwrap();
            self.hdrlen -= last.len();
            self.pktlen -= last.len();
        }
    }
    /// Remove a header with an index
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::headers::*; use packet_rs::Packet;
    /// let mut pkt = Packet::new(100);
    /// pkt.push(Ether::new());
    /// pkt.push(Vlan::new());
    /// pkt.push(IPv4::new());
    /// // vlan header is now removed from the packet
    /// pkt.remove(1);
    /// ```
    pub fn remove(&mut self, index: usize) -> () {
        if self.hdrs.len() != 0 && index < self.hdrs.len() {
            let remove = self.hdrs.remove(index);
            self.hdrlen -= remove.len();
            self.pktlen -= remove.len();
        }
    }
    /// Get immutable access to a header from the packet
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::headers::*; use packet_rs::Packet;
    /// let mut pkt = Packet::new(100);
    /// pkt.push(Ether::new());
    /// // use this API for immutable access
    /// let x: &Ether = pkt.get_header("Ether").unwrap();
    /// println!("{}", x.etype());
    ///
    /// // use the Index trait of Packet to get Header
    /// let y: &Box<dyn Header> = &pkt["Ether"];
    /// // use the into trait of Header to get Ether header
    /// let x: &Ether = y.into();
    /// println!("{}", x.etype());
    ///
    /// // use the Index trait of Packet and convert to Ether header
    /// let x: &Ether = (&pkt["Ether"]).into();
    /// println!("{}", x.etype());
    /// ```
    pub fn get_header<'a, T: 'static>(&'a self, index: &'a str) -> Result<&'a T, String> {
        let y: &Box<dyn Header> = &self[index];
        match y.as_any().downcast_ref::<T>() {
            Some(b) => Ok(b),
            None => Err(format!("{} header not found", index)),
        }
    }
    /// Get mutable access to a header from the packet
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::headers::*; use packet_rs::Packet;
    /// let mut pkt = Packet::new(100);
    /// pkt.push(Ether::new());
    /// // use this API for mutable access
    /// let x: &mut Ether = pkt.get_header_mut("Ether").unwrap();
    /// x.set_etype(0x9999);
    ///
    /// // use the IndexMut trait of Packet and convert to mutable Ether header
    /// let x: &mut Box<dyn Header> = &mut pkt["Ether"];
    /// let x: &mut Ether = x.into();
    /// x.set_etype(0x9999);
    /// ```
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

#[pymethods]
impl Packet {
    #[cfg(feature = "python-module")]
    fn __add__(lhs: PyObject, rhs: PyObject) -> PyResult<Packet> {
        let gil = Python::acquire_gil();
        let mut x: Packet = lhs.extract(gil.python()).unwrap();
        let y: Box<dyn Header> = rhs.extract(gil.python())?;
        x.push_boxed_header(y);
        Ok(x)
    }
    #[cfg(feature = "python-module")]
    fn __getitem1__(slf: &PyCell<Self>, index: String) -> PyObject {
        let gil = ::pyo3::Python::acquire_gil();
        let mut pkt = slf.try_borrow_mut().unwrap();
        let hdr: &mut Box<dyn Header> = &mut pkt[&index];
        hdr.to_object(gil.python())
    }
    #[cfg(feature = "python-module")]
    fn __getitem__(&mut self, index: String) -> PyObject {
        let gil = ::pyo3::Python::acquire_gil();
        let hdr: &mut Box<dyn Header> = &mut self[&index];
        println!("Getting {}", hdr.name());
        hdr.to_object(gil.python())
    }
    /*
    fn __getitem2__(mut slf : PyRef<'_, Self>, index: String) -> PyRef<'_, Ether> {
        let gil = ::pyo3::Python::acquire_gil();
        let hdr: & Box<dyn Header> = & slf[&index];
        let e = &<Ether>::from(hdr);
        let n = PyCell::new(gil.python(), e).unwrap();
        let k = n.borrow();
        k
    }
    */
    #[cfg(feature = "python-module")]
    fn __setitem__(&mut self, index: String, value: Ether) -> () {
        let x: &mut Ether = self.get_header_mut(index.as_str()).unwrap();
        x.replace(&value);
    }
    #[new]
    /// Create a new Packet instance of size "pktlen". Length does not change on pushing or popping headers
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::Packet;
    /// let pkt = Packet::new(100);
    /// pkt.show();
    /// ```
    pub fn new(pktlen: usize) -> Packet {
        Packet {
            hdrs: Vec::new(),
            hdrlen: 0,
            pktlen,
        }
    }
    /// Compare this packet with another Packet
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::Packet;
    /// let pkt = Packet::new(100);
    /// let other = Packet::new(100);
    /// pkt.compare(&other);
    /// ```
    pub fn compare(&self, pkt: &Packet) -> bool {
        let a = pkt.to_vec();
        self.compare_with_slice(a.as_slice())
    }
    #[inline]
    /// Compare this packet with an array of bytes
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::Packet;
    /// let pkt = Packet::new(100);
    /// let other = Packet::new(100);
    /// pkt.compare_with_slice(other.to_vec().as_slice());
    /// ```
    pub fn compare_with_slice(&self, b: &[u8]) -> bool {
        if self.pktlen != b.len() {
            println!("this {} other {}", self.pktlen, b.len());
            return false;
        }
        let a = self.to_vec();
        let matching = a.iter().zip(b).filter(|&(a, b)| a == b).count();
        if self.pktlen != matching || b.len() != matching {
            println!(
                "this {} other {}, matching upto {} bytes",
                self.pktlen,
                b.len(),
                matching
            );
            return false;
        }
        true
    }
    /// Display the packet contents
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
    /// Copies packet into a new vec
    /// # Example
    ///
    /// ```
    /// # #[macro_use] extern crate packet_rs; use packet_rs::Packet;
    /// let pkt = Packet::new(100);
    /// let v = pkt.to_vec();
    /// ```
    pub fn to_vec(&self) -> Vec<u8> {
        let mut r = Vec::new();
        for s in &self.hdrs {
            r.extend_from_slice(&s.to_vec().as_slice());
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
    /// Return length of the packet
    pub fn len(&self) -> usize {
        self.pktlen
    }
    #[staticmethod]
    pub fn ethernet(dst: &str, src: &str, etype: u16) -> Ether {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&dst.to_mac_bytes());
        data.extend_from_slice(&src.to_mac_bytes());
        data.extend_from_slice(&etype.to_be_bytes());
        Ether::from(data)
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
        let ptype: u16 = EtherType::IPV4 as u16;
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
        let b1: u16 = (ErspanVersion::II as u16) << 12 | vlan;
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
        let b1: u16 = (ErspanVersion::III as u16) << 12 | vlan;
        let b2: u16 = (cos as u16) << 13 | (en as u16) << 11 | (t as u16) << 10 | session_id;
        data.extend_from_slice(&b1.to_be_bytes());
        data.extend_from_slice(&b2.to_be_bytes());
        data.extend_from_slice(&timestamp.to_be_bytes());
        data.extend_from_slice(&sgt.to_be_bytes());
        data.extend_from_slice(&ft_d_other.to_be_bytes());
        ERSPAN3::from(data)
    }
    #[staticmethod]
    pub fn mpls(label: u32, exp: u8, bos: u8, ttl: u8) -> MPLS {
        let w: u32 = label << 20 | (exp as u32) << 23 | (bos as u32) << 24 | ttl as u32;
        MPLS::from(w.to_be_bytes().to_vec())
    }
    #[staticmethod]
    pub fn snap(oui: u32, code: u16) -> SNAP {
        let oui_01: u16 = oui as u16;
        let oui_2: u8 = (oui >> 16) as u8;
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&oui_01.to_be_bytes());
        data.extend_from_slice(&oui_2.to_be_bytes());
        data.extend_from_slice(&code.to_be_bytes());
        SNAP::from(data)
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

#[test]
fn set_get_octets_test() {
    let mut dips = Vec::new();
    dips.push(String::from("FFFF::FFFF").to_ipv6_bytes());
    dips.push(String::from("7FFF::FFFF").to_ipv6_bytes());
    dips.push(String::from("FFF7::FFFF").to_ipv6_bytes());
    dips.push(String::from("FFFF::FFF7").to_ipv6_bytes());
    dips.push(String::from("FFFF::7FFF").to_ipv6_bytes());
    dips.push(String::from("1111::FFFF").to_ipv6_bytes());
    dips.push(String::from("8888::FFFF").to_ipv6_bytes());
    dips.push(String::from("FFFF::1111").to_ipv6_bytes());
    dips.push(String::from("FFFF::8888").to_ipv6_bytes());
    dips.push(String::from("8888::1111").to_ipv6_bytes());
    dips.push(String::from("2001:3001:4001::FFFF").to_ipv6_bytes());
    dips.push(String::from("FFFF:4001:3001::2001").to_ipv6_bytes());
    dips.push(String::from("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF").to_ipv6_bytes());
    dips.push(String::from("1111:1111:1111:1111:1111:1111:1111:1111").to_ipv6_bytes());
    dips.push(String::from("8888:8888:8888:8888:8888:8888:8888:8888").to_ipv6_bytes());
    dips.push(String::from("FFFF:4001:3001:2001:2001:3001:4001:FFFF").to_ipv6_bytes());
    dips.push(String::from("2001:3001:4001:FFFF:FFFF:4001:3001:2001").to_ipv6_bytes());
    let sips = dips.clone();

    let mut ipv6 = IPv6::new();
    for a in dips {
        ipv6.set_bytes(IPv6::dst_msb(), IPv6::dst_lsb(), &a);
        let b = ipv6.bytes(IPv6::dst_msb(), IPv6::dst_lsb());
        let b = b.as_slice();
        assert_eq!(a.iter().zip(b).filter(|&(a, b)| a == b).count(), 16);
    }
    for a in sips {
        ipv6.set_bytes(IPv6::src_msb(), IPv6::src_lsb(), &a);
        let b = ipv6.bytes(IPv6::src_msb(), IPv6::src_lsb());
        let b = b.as_slice();
        assert_eq!(a.iter().zip(b).filter(|&(a, b)| a == b).count(), 16);
    }
}

impl<'a> PacketSlice<'a> {
    pub fn new(pktlen: usize) -> PacketSlice<'a> {
        PacketSlice {
            hdrs: Vec::new(),
            hdrlen: 0,
            pktlen,
        }
    }
    pub fn push(&mut self, hdr: impl Header + 'a) {
        self.hdrlen += hdr.len();
        self.hdrs.insert(0, Box::new(hdr));
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
}
