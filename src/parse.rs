use crate::headers::*;
use crate::types::*;
use crate::PacketSlice;

pub fn parse<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let mut pkt = parse_ethernet(arr);
    pkt.pktlen = arr.len();
    pkt
}

#[inline]
fn parse_ethernet<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let eth = EtherSlice::from_slice(&arr[0..Ether::size()]);
    let etype = eth.etype() as u16;
    let mut p = match etype {
        ETHERTYPE_DOT1Q => parse_vlan(&arr[Ether::size()..]),
        ETHERTYPE_ARP => parse_arp(&arr[Ether::size()..]),
        ETHERTYPE_IPV4 => parse_ipv4(&arr[Ether::size()..]),
        ETHERTYPE_IPV6 => parse_ipv6(&arr[Ether::size()..]),
        ETHERTYPE_MPLS => parse_mpls(&arr[Ether::size()..]),
        _ => accept(&arr[Ether::size()..]),
    };
    p.push(eth);
    p
}
#[inline]
fn parse_mpls<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let mpls = MPLSSlice::from_slice(&arr[0..MPLS::size()]);
    let bos = mpls.bos();
    if bos == 1 {
        parse_mpls_bos(&arr[MPLS::size()..])
    } else {
        parse_mpls(&arr[MPLS::size()..])
    }
}
#[inline]
fn parse_mpls_bos<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let mpls = MPLS::from(arr[0..MPLS::size()].to_vec());
    let mut p = match IpType::from_u8(arr[MPLS::size()] >> 4 & 0xf) {
        Some(IpType::V4) => parse_ipv4(&arr[MPLS::size()..]),
        Some(IpType::V6) => parse_ipv6(&arr[MPLS::size()..]),
        _ => parse_ethernet(&arr[MPLS::size()..]),
    };
    p.push(mpls);
    p
}
#[inline]
fn parse_vlan<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let vlan = VlanSlice::from_slice(&arr[0..Vlan::size()]);
    let etype = vlan.etype() as u16;
    let mut p = match etype {
        ETHERTYPE_DOT1Q => parse_vlan(&arr[Vlan::size()..]),
        ETHERTYPE_ARP => parse_arp(&arr[Vlan::size()..]),
        ETHERTYPE_IPV4 => parse_ipv4(&arr[Vlan::size()..]),
        ETHERTYPE_IPV6 => parse_ipv6(&arr[Vlan::size()..]),
        ETHERTYPE_MPLS => parse_mpls(&arr[Vlan::size()..]),
        _ => accept(&arr[Vlan::size()..]),
    };
    p.push(vlan);
    p
}
#[inline]
fn parse_ipv4<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let ipv4 = IPv4Slice::from_slice(&arr[0..IPv4::size()]);
    let proto = ipv4.protocol() as u8;
    let mut p = match proto as u8 {
        IP_PROTOCOL_ICMP => parse_icmp(&arr[IPv4::size()..]),
        IP_PROTOCOL_IPIP => parse_ipv4(&arr[IPv4::size()..]),
        IP_PROTOCOL_TCP => parse_tcp(&arr[IPv4::size()..]),
        IP_PROTOCOL_UDP => parse_udp(&arr[IPv4::size()..]),
        IP_PROTOCOL_IPV6 => parse_ipv6(&arr[IPv4::size()..]),
        //IP_PROTOCOL_GRE => parse_gre(pkt, &arr[IPv4::size()..]),
        _ => accept(&arr[IPv4::size()..]),
    };
    p.push(ipv4);
    p
}
#[inline]
fn parse_ipv6<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let ipv6 = IPv6Slice::from_slice(&arr[0..IPv6::size()]);
    let next_hdr = ipv6.next_hdr() as u8;
    let mut p = match next_hdr as u8 {
        IP_PROTOCOL_ICMPV6 => parse_icmp(&arr[IPv6::size()..]),
        IP_PROTOCOL_IPIP => parse_ipv4(&arr[IPv6::size()..]),
        IP_PROTOCOL_TCP => parse_tcp(&arr[IPv6::size()..]),
        IP_PROTOCOL_UDP => parse_udp(&arr[IPv6::size()..]),
        IP_PROTOCOL_IPV6 => parse_ipv6(&arr[IPv6::size()..]),
        //IP_PROTOCOL_GRE => parse_gre(&arr[IPv6::size()..]),
        _ => accept(&arr[IPv6::size()..]),
    };
    p.push(ipv6);
    p
}
#[inline]
fn parse_arp<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let arp = ARPSlice::from_slice(&arr[0..ARP::size()]);
    let mut p = accept(&arr[ARP::size()..]);
    p.push(arp);
    p
}
#[inline]
fn parse_icmp<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let icmp = ICMPSlice::from_slice(&arr[0..ICMP::size()]);
    let mut p = accept(&arr[ICMP::size()..]);
    p.push(icmp);
    p
}
#[inline]
fn parse_tcp<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let tcp = TCPSlice::from_slice(&arr[0..TCP::size()]);
    let mut p = accept(&arr[TCP::size()..]);
    p.push(tcp);
    p
}
#[inline]
fn parse_udp<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let udp = UDPSlice::from_slice(&arr[0..UDP::size()]);
    let dst = udp.dst() as u16;
    let mut p = match dst {
        UDP_PORT_VXLAN => parse_vxlan(&arr[UDP::size()..]),
        _ => accept(&arr[UDP::size()..]),
    };
    p.push(udp);
    p
}
#[inline]
fn parse_vxlan<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
    let vxlan = VxlanSlice::from_slice(&arr[0..Vxlan::size()]);
    let mut pkt = parse_ethernet(&arr[Vxlan::size()..]);
    pkt.push(vxlan);
    pkt
}
#[inline]
fn accept<'a>(_arr: &'a [u8]) -> PacketSlice<'a> {
    PacketSlice::new(0)
}
