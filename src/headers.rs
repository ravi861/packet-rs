pub use ::bitfield::bitfield;
pub use ::bitfield::BitRange;
pub use paste::paste;

pub trait Header {
    fn show(&self);
    fn octets(&self) -> Vec<u8>;
    fn clone(&self) -> Box<dyn Header + 'static>;
}

#[macro_export]
macro_rules! make_header {
    ( $name: ident $size: literal ($($field: ident: $start: literal-$end: literal),*) ) => {
        paste! {
            bitfield! {
                pub struct $name(MSB0 [u8]);
                u32;
                $(
                    pub $field, [<set_ $field>]: $end, $start;
                )*
            }
            impl<T: AsMut<[u8]> + AsRef<[u8]>> $name<T> {
                pub fn size(&self) -> u32 {
                    $size
                }
                $(
                    pub fn [<$field _size>](&self) -> u32 {
                        $end - $start + 1
                    }
                )*
                pub fn show(&self) {
                    println!("#### {:16} {} {}", stringify!($name), "Size  ", "Data");
                    println!("-------------------------------------------");
                    $(
                    print!("{:20}: {:4} : ", stringify!($field), $end - $start + 1);
                    if (($end - $start + 1) <= 8) {
                        let x: u8 = self.bit_range($end, $start);
                        print!("{:02}", x);
                    } else if (($end - $start + 1)%8 == 0){
                        let d = ($end - $start + 1)/8;
                        for i in ($start..(d*8 + $start)).step_by(8) {
                            let x: u8 = self.bit_range(i + 7, i);
                            print!("{:02x} ", x);
                        }
                    } else {
                        let d = ($end - $start + 1)/8;
                        let r = ($end - $start + 1)%8;
                        for i in ($start..(d*8 + $start)).step_by(8) {
                            let x: u8 = self.bit_range(i + 7, i);
                            print!("{:02} ", x);
                        }
                        let x: u8 = self.bit_range($end, $end - r);
                        print!("{:02}", x);
                    }
                    println!();
                    )*
                }
                pub fn bytes(&self) {
                    for i in (0..$size*8).step_by(8) {
                        let x: u8 = self.bit_range(i + 7, i);
                        print!("{:02x} ", x);
                        if (i == 120) {
                            println!();
                        }
                    }
                    println!();
                }
                pub fn clone(&self) -> $name<Vec<u8>> {
                    $name(self.octets())
                }
                pub fn octets(&self) -> Vec<u8> {
                    // let mut x: [u8; $size] = [0; $size];
                    let mut x: Vec<u8> = vec![0; $size];
                    for i in (0..$size*8).step_by(8) {
                        x[i/8] = self.bit_range(i + 7, i);
                    }
                    x
                }
            }
            impl Header for $name<Vec<u8>> {
                fn show(&self) {
                    self.show();
                }
                fn octets(&self) -> Vec<u8>{
                    self.octets()
                }
                fn clone(&self) -> Box<dyn Header + 'static> {
                    Box::new(self.clone())
                }
            }
        }
    }
}

// ethernet header
make_header!(
Ethernet 14
(
    dst: 0-47,
    src: 48-95,
    etype: 96-111
)
);

// vlan header
make_header!(
Vlan 4
(
    pcp: 0-2,
    cfi: 3-3,
    vid: 4-15,
    etype: 16-31
)
);

// ipv4 header
make_header!(
IPv4 20
(
    version: 0-3,
    ihl: 4-7,
    diffserv: 8-15,
    total_len: 16-31,
    identification: 32-47,
    flags: 48-50,
    frag_startset: 51-63,
    ttl: 64-71,
    protocol: 72-79,
    header_checksum: 80-95,
    src: 96-127,
    dst: 128-159
)
);

// ipv6 header
make_header!(
IPv6 40
(
    version: 0-3,
    traffic_class: 4-11,
    flow_label: 12-31,
    payload_len: 32-47,
    next_hdr: 48-55,
    hop_limit: 56-63,
    src: 64-191,
    dst: 192-319
)
);

// tcp header
make_header!(
TCP 20
(
    src: 0-15,
    dst_port: 16-31,
    seq_no: 32-63,
    ack_no: 64-95,
    data_startset: 96-99,
    res: 100-103,
    flags: 104-111,
    window: 112-127,
    checksum: 128-143,
    urgent_ptr: 144-159
)
);

// udp header
make_header!(
UDP 8
(
    src: 0-15,
    dst: 16-31,
    length: 32-47,
    checksum: 48-63
)
);
