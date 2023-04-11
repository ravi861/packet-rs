//! # Helper utilities to generate packets

use crate::headers::*;
use crate::types::*;
use crate::Packet;

pub fn create_eth_packet(
    eth_dst: &str,
    eth_src: &str,
    vlan_enable: bool,
    vlan_vid: u16,
    vlan_pcp: u8,
    etype: u16,
    payload: &[u8],
) -> Packet {
    let mut pkt = Packet::new();
    if vlan_enable {
        pkt.push(Packet::ethernet(eth_dst, eth_src, EtherType::DOT1Q as u16));
        pkt.push(Packet::vlan(vlan_pcp, 0, vlan_vid, etype));
    } else {
        pkt.push(Packet::ethernet(eth_dst, eth_src, etype));
    }
    pkt.set_payload(payload);
    pkt
}

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
    payload: &[u8],
) -> Packet {
    let mut pkt = create_eth_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        EtherType::ARP as u16,
        payload,
    );
    pkt.push(Packet::arp(
        opcode, sender_mac, target_mac, sender_ip, target_ip,
    ));
    pkt
}

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
    payload: &[u8],
) -> Packet {
    let mut pkt = create_eth_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        EtherType::IPV4 as u16,
        payload,
    );
    let pktlen = IPv4::size() + payload.len();
    let ipv4 = Packet::ipv4(
        ip_ihl,
        ip_tos,
        ip_id,
        ip_ttl,
        ip_frag,
        ip_proto,
        ip_src,
        ip_dst,
        pktlen as u16,
    );
    pkt.push(ipv4);
    pkt
}

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
    payload: &[u8],
) -> Packet {
    let mut pkt = create_eth_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        EtherType::IPV6 as u16,
        payload,
    );
    let ipv6 = Packet::ipv6(
        ip_traffic_class,
        ip_flow_label,
        ip_next_hdr,
        ip_hop_limit,
        ip_src,
        ip_dst,
        payload.len() as u16,
    );
    pkt.push(ipv6);
    pkt
}

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
    payload: &[u8],
) -> Packet {
    let mut pkt = create_ipv4_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_ihl,
        ip_src,
        ip_dst,
        IpProtocol::TCP as u8,
        ip_tos,
        ip_ttl,
        ip_id,
        ip_frag,
        ip_options,
        payload,
    );
    let ipv4: &mut IPv4 = (&mut pkt["IPv4"]).into();
    ipv4.set_total_len(ipv4.total_len() + TCP::size() as u64);
    let chksum = Packet::ipv4_checksum(ipv4.to_vec().as_slice());
    ipv4.set_header_checksum(chksum as u64);

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
    payload: &[u8],
) -> Packet {
    let mut pkt = create_ipv4_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_ihl,
        ip_src,
        ip_dst,
        IpProtocol::UDP as u8,
        ip_tos,
        ip_ttl,
        ip_id,
        ip_frag,
        ip_options,
        payload,
    );
    let ipv4: &mut IPv4 = (&mut pkt["IPv4"]).into();
    ipv4.set_total_len(ipv4.total_len() + UDP::size() as u64);
    let chksum = Packet::ipv4_checksum(ipv4.to_vec().as_slice());
    ipv4.set_header_checksum(chksum as u64);

    let l4_len = UDP::size() + payload.len();
    let udp = Packet::udp(udp_src, udp_dst, l4_len as u16);
    pkt.push(udp);
    pkt
}

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
    payload: &[u8],
) -> Packet {
    let mut pkt = create_ipv4_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_ihl,
        ip_src,
        ip_dst,
        IpProtocol::ICMP as u8,
        ip_tos,
        ip_ttl,
        ip_id,
        ip_frag,
        ip_options,
        payload,
    );
    let ipv4: &mut IPv4 = (&mut pkt["IPv4"]).into();
    ipv4.set_total_len(ipv4.total_len() + ICMP::size() as u64);
    let chksum = Packet::ipv4_checksum(ipv4.to_vec().as_slice());
    ipv4.set_header_checksum(chksum as u64);

    let icmp = Packet::icmp(icmp_type, icmp_code);
    pkt.push(icmp);
    pkt
}

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

    let ip_proto = match IpType::try_from(ipkt_vec[0] >> 4 & 0xf as u8) {
        Ok(IpType::V4) => IpProtocol::IPIP,
        Ok(IpType::V6) => IpProtocol::IPV6,
        _ => IpProtocol::IPIP,
    };
    let pkt = create_ipv4_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_ihl,
        ip_src,
        ip_dst,
        ip_proto as u8,
        ip_tos,
        ip_ttl,
        ip_id,
        ip_frag,
        ip_options,
        ipkt_vec.as_slice(),
    );
    pkt
}

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

    let ip_nxt_hdr = match IpType::try_from(ipkt_vec[0] >> 4 & 0xf as u8) {
        Ok(IpType::V4) => IpProtocol::IPIP,
        Ok(IpType::V6) => IpProtocol::IPV6,
        _ => IpProtocol::IPIP,
    };
    let pkt = create_ipv6_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_traffic_class,
        ip_flow_label,
        ip_nxt_hdr as u8,
        ip_hop_limit,
        ip_src,
        ip_dst,
        ipkt_vec.as_slice(),
    );
    pkt
}

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
    payload: &[u8],
) -> Packet {
    let mut pkt = create_ipv6_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_traffic_class,
        ip_flow_label,
        IpProtocol::TCP as u8,
        ip_hop_limit,
        ip_src,
        ip_dst,
        payload,
    );
    let ipv6: &mut IPv6 = (&mut pkt["IPv6"]).into();
    ipv6.set_payload_len(ipv6.payload_len() + TCP::size() as u64);

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
    payload: &[u8],
) -> Packet {
    let mut pkt = create_ipv6_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_traffic_class,
        ip_flow_label,
        IpProtocol::UDP as u8,
        ip_hop_limit,
        ip_src,
        ip_dst,
        payload,
    );
    let ipv6: &mut IPv6 = (&mut pkt["IPv6"]).into();
    ipv6.set_payload_len(ipv6.payload_len() + UDP::size() as u64);

    let l4_len = UDP::size() + payload.len();
    let mut udp = Packet::udp(udp_src, udp_dst, l4_len as u16);
    udp.set_checksum(0xffff);
    pkt.push(udp);
    pkt
}

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
    payload: &[u8],
) -> Packet {
    let mut pkt = create_ipv6_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_traffic_class,
        ip_flow_label,
        IpProtocol::ICMPV6 as u8,
        ip_hop_limit,
        ip_src,
        ip_dst,
        payload,
    );
    let ipv6: &mut IPv6 = (&mut pkt["IPv6"]).into();
    ipv6.set_payload_len(ipv6.payload_len() + ICMP::size() as u64);
    let icmp = Packet::icmp(icmp_type, icmp_code);
    pkt.push(icmp);
    pkt
}

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
    let ipkt_vec = inner_pkt.to_vec();
    let mut pkt = create_ipv4_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_ihl,
        ip_src,
        ip_dst,
        IpProtocol::UDP as u8,
        ip_tos,
        ip_ttl,
        ip_id,
        ip_frag,
        ip_options,
        ipkt_vec.as_slice(),
    );
    let ipv4: &mut IPv4 = (&mut pkt["IPv4"]).into();
    ipv4.set_total_len(ipv4.total_len() + (UDP::size() + Vxlan::size()) as u64);

    let l4_len = UDP::size() + Vxlan::size() + ipkt_vec.len();
    let udp = Packet::udp(udp_src, udp_dst, l4_len as u16);
    pkt.push(udp);
    pkt.push(Packet::vxlan(vxlan_vni));
    pkt
}

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
    let ipkt_vec = inner_pkt.to_vec();
    let mut pkt = create_ipv6_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_traffic_class,
        ip_flow_label,
        IpProtocol::UDP as u8,
        ip_hop_limit,
        ip_src,
        ip_dst,
        ipkt_vec.as_slice(),
    );
    let ipv6: &mut IPv6 = (&mut pkt["IPv6"]).into();
    ipv6.set_payload_len(ipv6.payload_len() + (UDP::size() + Vxlan::size()) as u64);

    let l4_len = UDP::size() + Vxlan::size() + ipkt_vec.len();
    let mut udp = Packet::udp(udp_src, udp_dst, l4_len as u16);
    udp.set_checksum(0xffff);
    pkt.push(udp);

    pkt.push(Packet::vxlan(vxlan_vni));

    pkt = pkt + inner_pkt;
    pkt
}

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
    let (proto, ipkt_vec) = match inner_pkt {
        Some(ref p) => {
            let ipkt_vec = p.to_vec();
            match ipkt_vec[0] >> 4 & 0xf {
                4 => (EtherType::IPV4 as u16, ipkt_vec),
                6 => (EtherType::IPV6 as u16, ipkt_vec),
                _ => (0, ipkt_vec),
            }
        }
        None => (0, Vec::new()),
    };
    let mut pktlen = GRE::size();
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

    let mut pkt = create_ipv4_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_ihl,
        ip_src,
        ip_dst,
        IpProtocol::GRE as u8,
        ip_tos,
        ip_ttl,
        ip_id,
        ip_frag,
        ip_options,
        ipkt_vec.as_slice(),
    );
    let ipv4: &mut IPv4 = (&mut pkt["IPv4"]).into();
    ipv4.set_total_len(ipv4.total_len() + pktlen as u64);
    let chksum = Packet::ipv4_checksum(ipv4.to_vec().as_slice());
    ipv4.set_header_checksum(chksum as u64);

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
    pkt
}

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
    let ipkt_vec = match inner_pkt {
        Some(ref p) => p.to_vec(),
        None => Vec::new(),
    };
    let mut pktlen = GRE::size() + ERSPAN2::size();

    if gre_seqnum != 0 {
        pktlen += GRESequenceNum::size();
    }
    pktlen += match inner_pkt {
        Some(ref p) => p.len(),
        None => 0,
    };

    let mut pkt = create_ipv4_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_ihl,
        ip_src,
        ip_dst,
        IpProtocol::GRE as u8,
        ip_tos,
        ip_ttl,
        ip_id,
        ip_frag,
        ip_options,
        ipkt_vec.as_slice(),
    );
    let ipv4: &mut IPv4 = (&mut pkt["IPv4"]).into();
    ipv4.set_total_len(ipv4.total_len() + pktlen as u64);
    let chksum = Packet::ipv4_checksum(ipv4.to_vec().as_slice());
    ipv4.set_header_checksum(chksum as u64);

    let mut gre = GRE::new();
    gre.set_proto(EtherType::ERSPANII as u64);
    if gre_seqnum != 0 {
        gre.set_seqnum_present(1 as u64);
    }
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
    pkt
}

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
    let ipkt_vec = match inner_pkt {
        Some(ref p) => p.to_vec(),
        None => Vec::new(),
    };
    let mut pktlen = GRE::size() + ERSPAN3::size();

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

    let mut pkt = create_ipv4_packet(
        eth_dst,
        eth_src,
        vlan_enable,
        vlan_vid,
        vlan_pcp,
        ip_ihl,
        ip_src,
        ip_dst,
        IpProtocol::GRE as u8,
        ip_tos,
        ip_ttl,
        ip_id,
        ip_frag,
        ip_options,
        ipkt_vec.as_slice(),
    );
    let ipv4: &mut IPv4 = (&mut pkt["IPv4"]).into();
    ipv4.set_total_len(ipv4.total_len() + pktlen as u64);
    let chksum = Packet::ipv4_checksum(ipv4.to_vec().as_slice());
    ipv4.set_header_checksum(chksum as u64);

    let mut gre = GRE::new();
    gre.set_proto(EtherType::ERSPANIII as u64);
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
