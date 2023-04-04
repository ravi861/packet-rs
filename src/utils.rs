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
    let mut pkt = create_eth_packet(
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
    let mut pkt = create_eth_packet(
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
    let mut pkt = create_eth_packet(
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
    let mut pkt = create_ipv4_packet(
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
    let mut pkt = create_ipv4_packet(
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
    let mut pkt = create_ipv4_packet(
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

    let ip_proto = match IpType::from_u8(ipkt_vec[0] >> 4 & 0xf as u8) {
        Some(IpType::V4) => IP_PROTOCOL_IPIP,
        Some(IpType::V6) => IP_PROTOCOL_IPV6,
        _ => IP_PROTOCOL_IPIP,
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

    let ip_next_hdr = match IpType::from_u8(ipkt_vec[0] >> 4 & 0xf as u8) {
        Some(IpType::V4) => IP_PROTOCOL_IPIP,
        Some(IpType::V6) => IP_PROTOCOL_IPV6,
        _ => IP_PROTOCOL_IPIP,
    };
    let mut pkt = create_ipv6_packet(
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
    let mut pkt = create_ipv6_packet(
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
    let mut pkt = create_ipv6_packet(
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
    let mut pkt = create_ipv6_packet(
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
    let pktlen =
        ETHERNET_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN + inner_pkt.to_vec().len();
    let mut pkt = create_ipv4_packet(
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
    let pktlen =
        ETHERNET_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN + VXLAN_HDR_LEN + inner_pkt.to_vec().len();
    let mut pkt = create_ipv6_packet(
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

    let mut pkt = create_ipv4_packet(
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

    let mut pkt = create_ipv4_packet(
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

    let mut pkt = create_ipv4_packet(
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
