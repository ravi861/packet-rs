pub enum IpType {
    V4 = 4,
    V6 = 6,
}
impl IpType {
    pub fn from_u8(value: u8) -> Option<IpType> {
        match value {
            4 => Some(IpType::V4),
            6 => Some(IpType::V6),
            _ => None,
        }
    }
}

pub enum IpProtocol {
    ICMP = 1,
    IPIP = 4,
    TCP = 6,
    UDP = 17,
    IPV6 = 41,
    GRE = 47,
    ICMPV6 = 58,
}
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

pub enum EtherType {
    IPV4 = 0x0800,
    ARP = 0x0806,
    DOT1Q = 0x8100,
    IPV6 = 0x86DD,
    MPLS = 0x8847,
    ERSPANII = 0x88be,
    ERSPANIII = 0x22eb,
}
impl EtherType {
    pub fn from_u16(value: u16) -> Option<EtherType> {
        match value {
            0x0800 => Some(EtherType::IPV4),
            0x0806 => Some(EtherType::ARP),
            0x8100 => Some(EtherType::DOT1Q),
            0x86dd => Some(EtherType::IPV6),
            0x8847 => Some(EtherType::MPLS),
            0x88be => Some(EtherType::ERSPANII),
            0x22eb => Some(EtherType::ERSPANIII),
            _ => None,
        }
    }
}
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

pub enum ErspanVersion {
    II = 1,
    III = 2,
}
pub const ERSPAN_II_VERSION: u8 = 1;
pub const ERSPAN_III_VERSION: u8 = 2;
