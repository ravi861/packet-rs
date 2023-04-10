use crate::headers::*;
use crate::types::*;
use crate::Packet;

pub fn parse(arr: &[u8]) -> Packet {
    let length: u16 = ((arr[12] as u16) << 8) | arr[13] as u16;
    if length < 1500 {
        parse_dot3(arr)
    } else {
        parse_ethernet(arr)
    }
}
pub fn parse_dot3(arr: &[u8]) -> Packet {
    let dot3 = Dot3::from(arr[0..Dot3::size()].to_vec());
    let mut pkt = parse_llc(&arr[Dot3::size()..]);
    pkt.insert(dot3);
    pkt
}
pub fn parse_llc(arr: &[u8]) -> Packet {
    let llc = LLC::from(arr[0..LLC::size()].to_vec());
    let mut pkt = if arr[0] == 0xAA && arr[1] == 0xAA && arr[2] == 0x03 {
        parse_snap(&arr[LLC::size()..])
    } else {
        accept(&arr[LLC::size()..])
    };
    pkt.insert(llc);
    pkt
}
pub fn parse_snap(arr: &[u8]) -> Packet {
    let snap = SNAP::from(arr[0..SNAP::size()].to_vec());
    let mut pkt = accept(&arr[SNAP::size()..]);
    pkt.insert(snap);
    pkt
}
pub fn parse_ethernet(arr: &[u8]) -> Packet {
    let eth = Ether::from(arr[0..Ether::size()].to_vec());
    let etype = EtherType::try_from(eth.etype() as u16);
    let mut pkt = match etype {
        Ok(EtherType::DOT1Q) => parse_vlan(&arr[Ether::size()..]),
        Ok(EtherType::ARP) => parse_arp(&arr[Ether::size()..]),
        Ok(EtherType::IPV4) => parse_ipv4(&arr[Ether::size()..]),
        Ok(EtherType::IPV6) => parse_ipv6(&arr[Ether::size()..]),
        Ok(EtherType::MPLS) => parse_mpls(&arr[Ether::size()..]),
        _ => accept(&arr[Ether::size()..]),
    };
    pkt.insert(eth);
    pkt
}
pub fn parse_vlan(arr: &[u8]) -> Packet {
    let vlan = Vlan::from(arr[0..Vlan::size()].to_vec());
    let etype = EtherType::try_from(vlan.etype() as u16);
    let mut pkt = match etype {
        Ok(EtherType::DOT1Q) => parse_vlan(&arr[Vlan::size()..]),
        Ok(EtherType::ARP) => parse_arp(&arr[Vlan::size()..]),
        Ok(EtherType::IPV4) => parse_ipv4(&arr[Vlan::size()..]),
        Ok(EtherType::IPV6) => parse_ipv6(&arr[Vlan::size()..]),
        Ok(EtherType::MPLS) => parse_mpls(&arr[Vlan::size()..]),
        _ => accept(&arr[Vlan::size()..]),
    };
    pkt.insert(vlan);
    pkt
}
pub fn parse_mpls(arr: &[u8]) -> Packet {
    let mpls = MPLS::from(arr[0..MPLS::size()].to_vec());
    let bos = mpls.bos();
    let mut pkt = if bos == 1 {
        parse_mpls_bos(&arr[MPLS::size()..])
    } else {
        parse_mpls(&arr[MPLS::size()..])
    };
    pkt.insert(mpls);
    pkt
}
pub fn parse_mpls_bos(arr: &[u8]) -> Packet {
    let mpls = MPLS::from(arr[0..MPLS::size()].to_vec());
    let mut pkt = match IpType::try_from(arr[MPLS::size()] >> 4 & 0xf) {
        Ok(IpType::V4) => parse_ipv4(&arr[MPLS::size()..]),
        Ok(IpType::V6) => parse_ipv6(&arr[MPLS::size()..]),
        _ => parse_ethernet(&arr[MPLS::size()..]),
    };
    pkt.insert(mpls);
    pkt
}
pub fn parse_ipv4(arr: &[u8]) -> Packet {
    let ipv4 = IPv4::from(arr[0..IPv4::size()].to_vec());
    let proto = IpProtocol::try_from(ipv4.protocol() as u8);
    let mut pkt = match proto {
        Ok(IpProtocol::ICMP) => parse_icmp(&arr[IPv4::size()..]),
        Ok(IpProtocol::IPIP) => parse_ipv4(&arr[IPv4::size()..]),
        Ok(IpProtocol::TCP) => parse_tcp(&arr[IPv4::size()..]),
        Ok(IpProtocol::UDP) => parse_udp(&arr[IPv4::size()..]),
        Ok(IpProtocol::IPV6) => parse_ipv6(&arr[IPv4::size()..]),
        Ok(IpProtocol::GRE) => parse_gre(&arr[IPv4::size()..]),
        _ => accept(&arr[IPv4::size()..]),
    };
    pkt.insert(ipv4);
    pkt
}
pub fn parse_ipv6(arr: &[u8]) -> Packet {
    let ipv6 = IPv6::from(arr[0..IPv6::size()].to_vec());
    let next_hdr = IpProtocol::try_from(ipv6.next_hdr() as u8);
    let mut pkt = match next_hdr {
        Ok(IpProtocol::ICMPV6) => parse_icmp(&arr[IPv6::size()..]),
        Ok(IpProtocol::IPIP) => parse_ipv4(&arr[IPv6::size()..]),
        Ok(IpProtocol::TCP) => parse_tcp(&arr[IPv6::size()..]),
        Ok(IpProtocol::UDP) => parse_udp(&arr[IPv6::size()..]),
        Ok(IpProtocol::IPV6) => parse_ipv6(&arr[IPv6::size()..]),
        Ok(IpProtocol::GRE) => parse_gre(&arr[IPv6::size()..]),
        _ => accept(&arr[IPv6::size()..]),
    };
    pkt.insert(ipv6);
    pkt
}
pub fn parse_gre(arr: &[u8]) -> Packet {
    let gre = GRE::from(arr[0..GRE::size()].to_vec());
    let proto = EtherType::try_from(gre.proto() as u16);
    let chksum_present = gre.chksum_present();
    let seqnum_present = gre.seqnum_present();
    let key_present = gre.key_present();
    let mut offset = 0;
    offset += GRE::size();
    let gco = if chksum_present == 1 {
        let p = Some(GREChksumOffset::from(
            arr[offset..offset + GREChksumOffset::size()].to_vec(),
        ));
        offset += GREChksumOffset::size();
        p
    } else {
        None
    };
    let gk = if key_present == 1 {
        let p = Some(GREKey::from(arr[offset..offset + GREKey::size()].to_vec()));
        offset += GREKey::size();
        p
    } else {
        None
    };
    let gsn = if seqnum_present == 1 {
        let p = Some(GRESequenceNum::from(
            arr[offset..offset + GRESequenceNum::size()].to_vec(),
        ));
        offset += GRESequenceNum::size();
        p
    } else {
        None
    };
    let mut pkt = match proto {
        Ok(EtherType::IPV4) => parse_ipv4(&arr[offset..]),
        Ok(EtherType::IPV6) => parse_ipv6(&arr[offset..]),
        Ok(EtherType::ERSPANII) => parse_erspan2(&arr[offset..]),
        Ok(EtherType::ERSPANIII) => parse_erspan3(&arr[offset..]),
        _ => accept(&arr[offset..]),
    };
    if let Some(p) = gco {
        pkt.insert(p);
    }
    if let Some(p) = gk {
        pkt.insert(p);
    }
    if let Some(p) = gsn {
        pkt.insert(p);
    }
    pkt.insert(gre);
    pkt
}
pub fn parse_erspan2(arr: &[u8]) -> Packet {
    let erspan2 = ERSPAN2::from(arr[0..ERSPAN2::size()].to_vec());
    let mut pkt = parse_ethernet(&arr[ERSPAN2::size()..]);
    pkt.insert(erspan2);
    pkt
}
pub fn parse_erspan3(arr: &[u8]) -> Packet {
    let erspan3 = ERSPAN3::from(arr[0..ERSPAN3::size()].to_vec());
    let o = erspan3.o();
    let mut offset = 0;
    offset += ERSPAN3::size();
    let platform = if o == 1 {
        let p = Some(ERSPANPLATFORM::from(
            arr[offset..offset + ERSPANPLATFORM::size()].to_vec(),
        ));
        offset += ERSPANPLATFORM::size();
        p
    } else {
        None
    };
    let mut pkt = parse_ethernet(&arr[offset..]);
    if let Some(p) = platform {
        pkt.insert(p);
    }
    pkt.insert(erspan3);
    pkt
}
pub fn parse_arp(arr: &[u8]) -> Packet {
    let mut pkt = accept(&arr[ARP::size()..]);
    pkt.insert(ARP::from(arr[0..ARP::size()].to_vec()));
    pkt
}
pub fn parse_icmp(arr: &[u8]) -> Packet {
    let mut pkt = accept(&arr[ICMP::size()..]);
    pkt.insert(ICMP::from(arr[0..ICMP::size()].to_vec()));
    pkt
}
pub fn parse_tcp(arr: &[u8]) -> Packet {
    let mut pkt = accept(&arr[TCP::size()..]);
    pkt.insert(TCP::from(arr[0..TCP::size()].to_vec()));
    pkt
}
pub fn parse_udp(arr: &[u8]) -> Packet {
    let udp = UDP::from(arr[0..UDP::size()].to_vec());
    let dst = udp.dst() as u16;
    let mut pkt = match dst {
        UDP_PORT_VXLAN => parse_vxlan(&arr[UDP::size()..]),
        _ => accept(&arr[UDP::size()..]),
    };
    pkt.insert(udp);
    pkt
}
pub fn parse_vxlan(arr: &[u8]) -> Packet {
    let mut pkt = parse_ethernet(&arr[Vxlan::size()..]);
    pkt.insert(Vxlan::from(arr[0..Vxlan::size()].to_vec()));
    pkt
}
pub fn accept(arr: &[u8]) -> Packet {
    let mut pkt = Packet::new();
    pkt.set_payload(arr);
    pkt
}
