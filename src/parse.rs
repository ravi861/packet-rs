pub mod full {
    use crate::headers::*;
    use crate::types::*;
    use crate::Packet;

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
    #[inline]
    fn parse_ethernet(pkt: &mut Packet, arr: &[u8]) {
        let eth = Ether::from(arr[0..Ether::size()].to_vec());
        let etype = EtherType::try_from(eth.etype() as u16);
        pkt.push(eth);
        match etype {
            Ok(EtherType::DOT1Q) => parse_vlan(pkt, &arr[Ether::size()..]),
            Ok(EtherType::ARP) => parse_arp(pkt, &arr[Ether::size()..]),
            Ok(EtherType::IPV4) => parse_ipv4(pkt, &arr[Ether::size()..]),
            Ok(EtherType::IPV6) => parse_ipv6(pkt, &arr[Ether::size()..]),
            Ok(EtherType::MPLS) => parse_mpls(pkt, &arr[Ether::size()..]),
            _ => accept(),
        }
    }
    fn parse_vlan(pkt: &mut Packet, arr: &[u8]) {
        let vlan = Vlan::from(arr[0..Vlan::size()].to_vec());
        let etype = EtherType::try_from(vlan.etype() as u16);
        pkt.push(vlan);
        match etype {
            Ok(EtherType::DOT1Q) => parse_vlan(pkt, &arr[Vlan::size()..]),
            Ok(EtherType::ARP) => parse_arp(pkt, &arr[Vlan::size()..]),
            Ok(EtherType::IPV4) => parse_ipv4(pkt, &arr[Vlan::size()..]),
            Ok(EtherType::IPV6) => parse_ipv6(pkt, &arr[Vlan::size()..]),
            Ok(EtherType::MPLS) => parse_mpls(pkt, &arr[Vlan::size()..]),
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
        match IpType::try_from(arr[MPLS::size()] >> 4 & 0xf) {
            Ok(IpType::V4) => parse_ipv4(pkt, &arr[MPLS::size()..]),
            Ok(IpType::V6) => parse_ipv6(pkt, &arr[MPLS::size()..]),
            _ => parse_ethernet(pkt, &arr[MPLS::size()..]),
        };
    }
    #[inline]
    fn parse_ipv4(pkt: &mut Packet, arr: &[u8]) {
        let ipv4 = IPv4::from(arr[0..IPv4::size()].to_vec());
        let proto = IpProtocol::try_from(ipv4.protocol() as u8);
        pkt.push(ipv4);
        match proto {
            Ok(IpProtocol::ICMP) => parse_icmp(pkt, &arr[IPv4::size()..]),
            Ok(IpProtocol::IPIP) => parse_ipv4(pkt, &arr[IPv4::size()..]),
            Ok(IpProtocol::TCP) => parse_tcp(pkt, &arr[IPv4::size()..]),
            Ok(IpProtocol::UDP) => parse_udp(pkt, &arr[IPv4::size()..]),
            Ok(IpProtocol::IPV6) => parse_ipv6(pkt, &arr[IPv4::size()..]),
            Ok(IpProtocol::GRE) => parse_gre(pkt, &arr[IPv4::size()..]),
            _ => accept(),
        }
    }
    fn parse_ipv6(pkt: &mut Packet, arr: &[u8]) {
        let ipv6 = IPv6::from(arr[0..IPv6::size()].to_vec());
        let next_hdr = IpProtocol::try_from(ipv6.next_hdr() as u8);
        pkt.push(ipv6);
        match next_hdr {
            Ok(IpProtocol::ICMPV6) => parse_icmp(pkt, &arr[IPv6::size()..]),
            Ok(IpProtocol::IPIP) => parse_ipv4(pkt, &arr[IPv6::size()..]),
            Ok(IpProtocol::TCP) => parse_tcp(pkt, &arr[IPv6::size()..]),
            Ok(IpProtocol::UDP) => parse_udp(pkt, &arr[IPv6::size()..]),
            Ok(IpProtocol::IPV6) => parse_ipv6(pkt, &arr[IPv6::size()..]),
            Ok(IpProtocol::GRE) => parse_gre(pkt, &arr[IPv6::size()..]),
            _ => accept(),
        }
    }
    fn parse_gre(pkt: &mut Packet, arr: &[u8]) {
        let gre = GRE::from(arr[0..GRE::size()].to_vec());
        let proto = EtherType::try_from(gre.proto() as u16);
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
            Ok(EtherType::IPV4) => parse_ipv4(pkt, &arr[offset..]),
            Ok(EtherType::IPV6) => parse_ipv6(pkt, &arr[offset..]),
            Ok(EtherType::ERSPANII) => parse_erspan2(pkt, &arr[offset..]),
            Ok(EtherType::ERSPANIII) => parse_erspan3(pkt, &arr[offset..]),
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
    #[inline]
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
    #[inline]
    fn parse_tcp(pkt: &mut Packet, arr: &[u8]) {
        let tcp = TCP::from(arr[0..TCP::size()].to_vec());
        pkt.push(tcp);
    }
    fn accept() {
        ()
    }
}

pub mod slice {
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
        let etype = EtherType::try_from(eth.etype() as u16);
        let mut p = match etype {
            Ok(EtherType::DOT1Q) => parse_vlan(&arr[Ether::size()..]),
            Ok(EtherType::ARP) => parse_arp(&arr[Ether::size()..]),
            Ok(EtherType::IPV4) => parse_ipv4(&arr[Ether::size()..]),
            Ok(EtherType::IPV6) => parse_ipv6(&arr[Ether::size()..]),
            Ok(EtherType::MPLS) => parse_mpls(&arr[Ether::size()..]),
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
        let mut p = match IpType::try_from(arr[MPLS::size()] >> 4 & 0xf) {
            Ok(IpType::V4) => parse_ipv4(&arr[MPLS::size()..]),
            Ok(IpType::V6) => parse_ipv6(&arr[MPLS::size()..]),
            _ => parse_ethernet(&arr[MPLS::size()..]),
        };
        p.push(mpls);
        p
    }
    #[inline]
    fn parse_vlan<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
        let vlan = VlanSlice::from_slice(&arr[0..Vlan::size()]);
        let etype = EtherType::try_from(vlan.etype() as u16);
        let mut p = match etype {
            Ok(EtherType::DOT1Q) => parse_vlan(&arr[Vlan::size()..]),
            Ok(EtherType::ARP) => parse_arp(&arr[Vlan::size()..]),
            Ok(EtherType::IPV4) => parse_ipv4(&arr[Vlan::size()..]),
            Ok(EtherType::IPV6) => parse_ipv6(&arr[Vlan::size()..]),
            Ok(EtherType::MPLS) => parse_mpls(&arr[Vlan::size()..]),
            _ => accept(&arr[Vlan::size()..]),
        };
        p.push(vlan);
        p
    }
    #[inline]
    fn parse_ipv4<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
        let ipv4 = IPv4Slice::from_slice(&arr[0..IPv4::size()]);
        let proto = IpProtocol::try_from(ipv4.protocol() as u8);
        let mut p = match proto {
            Ok(IpProtocol::ICMP) => parse_icmp(&arr[IPv4::size()..]),
            Ok(IpProtocol::IPIP) => parse_ipv4(&arr[IPv4::size()..]),
            Ok(IpProtocol::TCP) => parse_tcp(&arr[IPv4::size()..]),
            Ok(IpProtocol::UDP) => parse_udp(&arr[IPv4::size()..]),
            Ok(IpProtocol::IPV6) => parse_ipv6(&arr[IPv4::size()..]),
            //IP_PROTOCOL_GRE => parse_gre(pkt, &arr[IPv4::size()..]),
            _ => accept(&arr[IPv4::size()..]),
        };
        p.push(ipv4);
        p
    }
    #[inline]
    fn parse_ipv6<'a>(arr: &'a [u8]) -> PacketSlice<'a> {
        let ipv6 = IPv6Slice::from_slice(&arr[0..IPv6::size()]);
        let next_hdr = IpProtocol::try_from(ipv6.next_hdr() as u8);
        let mut p = match next_hdr {
            Ok(IpProtocol::ICMPV6) => parse_icmp(&arr[IPv6::size()..]),
            Ok(IpProtocol::IPIP) => parse_ipv4(&arr[IPv6::size()..]),
            Ok(IpProtocol::TCP) => parse_tcp(&arr[IPv6::size()..]),
            Ok(IpProtocol::UDP) => parse_udp(&arr[IPv6::size()..]),
            Ok(IpProtocol::IPV6) => parse_ipv6(&arr[IPv6::size()..]),
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
}
