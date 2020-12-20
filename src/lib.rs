#![allow(dead_code)]
extern crate bitfield;
extern crate paste;

// pub here means expose to outside of crate
pub mod dataplane;
pub mod headers;
pub mod packet;

use self::packet::*;

fn ipv4_packet(
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
    let mut pkt = Packet::new(pktlen as usize);
    let mut ip_len = pktlen - ETHERNET_HDR_LEN as u16;

    let mut etype: u16 = ETHERTYPE_IPV4;
    if vlan_enable {
        etype = ETHERTYPE_DOT1Q;
    }

    pkt.push(Packet::ethernet(eth_dst, eth_src, etype));

    if vlan_enable {
        pkt.push(Packet::vlan(vlan_pcp, 0, vlan_vid, ETHERTYPE_IPV6));
        ip_len -= VLAN_HDR_LEN as u16;
    }

    let ipv4 = Packet::ipv4(
        ip_ihl, ip_tos, ip_id, ip_ttl, ip_frag, ip_proto, ip_src, ip_dst, ip_len,
    );
    pkt.push(ipv4);
    pkt
}

fn ipv6_packet(
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
    let mut pkt = Packet::new(pktlen as usize);
    let mut ip_len = pktlen - ETHERNET_HDR_LEN as u16;

    let mut etype: u16 = ETHERTYPE_IPV6;
    if vlan_enable {
        etype = ETHERTYPE_DOT1Q;
    }

    pkt.push(Packet::ethernet(eth_dst, eth_src, etype));

    if vlan_enable {
        pkt.push(Packet::vlan(vlan_pcp, 0, vlan_vid, ETHERTYPE_IPV6));
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
    let mut pkt = ipv4_packet(
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
    let mut pkt = ipv4_packet(
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
    let mut pkt = ipv6_packet(
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
    pktlen: usize,
) -> Packet {
    let mut pkt = ipv6_packet(
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
    let mut l4_len = pktlen - IPV4_HDR_LEN - ETHERNET_HDR_LEN;
    if vlan_enable {
        l4_len -= VLAN_HDR_LEN;
    }
    let udp = Packet::udp(udp_src, udp_dst, l4_len as u16);
    pkt.push(udp);
    pkt
}
