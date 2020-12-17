pub use ::bitfield::bitfield;
pub use ::bitfield::BitRange;
pub use paste::paste;
pub use std::any::Any;

pub trait Header {
    fn show(&self);
    fn as_slice(&self) -> &[u8];
    fn clone(&self) -> Box<dyn Header>;
    fn name(&self) -> &str;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

#[macro_export]
macro_rules! make_header {
    (
        $name: ident $size: literal
        ( $($field: ident: $start: literal-$end: literal),* )
        $x:expr
    ) => {
        paste! {
            bitfield! {
                pub struct $name(MSB0 [u8]);
                u64;
                $(
                    pub $field, [<set_ $field>]: $end, $start;
                )*
            }
            impl $name<Vec<u8>> {
                pub fn new() -> $name<Vec<u8>> {
                    $name($x)
                }
            }
            impl<T: AsMut<[u8]> + AsRef<[u8]>> $name<T> {
                pub fn get_bytes(&self, msb: usize, lsb: usize) -> Vec<u8> {
                    let bit_len = ::bitfield::size_of::<u8>() * 8;
                    assert_eq!((msb-lsb+1)%bit_len, 0);
                    let mut value: Vec<u8> = Vec::new();
                    for i in (lsb..=msb).step_by(bit_len) {
                        let v: u8 = self.bit_range(i + 7, i);
                        value.push(v);
                    }
                    value
                }
                pub fn set_bytes(&mut self, msb: usize, lsb: usize, value: &[u8]) {
                    let bit_len = ::bitfield::size_of::<u8>() * 8;
                    assert_eq!(value.len() * bit_len, msb-lsb+1);
                    let mut iter = 0;
                    for i in (lsb..=msb).step_by(bit_len) {
                        self.set_bit_range(i + 7, i, value[iter]);
                        iter += 1;
                    }
                }
                pub fn size() -> usize {
                    $size
                }
                pub fn name(&self) -> &str {
                    stringify!($name)
                }
                $(
                    pub fn [<$field _size>]() -> usize {
                        $end - $start + 1
                    }
                    pub fn [<$field _lsb>]() -> usize {
                        $start
                    }
                    pub fn [<$field _msb>]() -> usize {
                        $end
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
                fn bytes(&self) {
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
                    $name(Vec::from(self.0.as_ref()))
                }
                pub fn as_slice(&self) -> &[u8] {
                    self.0.as_ref()
                }
            }
            impl<'a> Into<&'a mut $name<Vec<u8>>> for &'a mut Box<dyn Header> {
                fn into(self) -> &'a mut $name<Vec<u8>> {
                    let b = match self.as_any_mut().downcast_mut::<$name<Vec<u8>>>() {
                        Some(b) => b,
                        None => panic!("Header is not a {}", stringify!($name)),
                    };
                    b
                }
            }
            impl<'a> Into<&'a $name<Vec<u8>>> for &'a Box<dyn Header> {
                fn into(self) -> &'a $name<Vec<u8>> {
                    let b = match self.as_any().downcast_ref::<$name<Vec<u8>>>() {
                        Some(b) => b,
                        None => panic!("Header is not a {}", stringify!($name)),
                    };
                    b
                }
            }
            impl Header for $name<Vec<u8>> {
                fn show(&self) {
                    self.show();
                }
                fn as_slice(&self) -> &[u8] {
                    self.as_slice()
                }
                fn clone(&self) -> Box<dyn Header + 'static> {
                    Box::new(self.clone())
                }
                fn name(&self) -> &str {
                    self.name()
                }
                fn as_any(&self) -> &dyn Any {
                    self
                }
                fn as_any_mut(&mut self) -> &mut dyn Any {
                    self
                }
            }
        }
    };
    (
        $name: ident $size: literal
        ( $($field: ident: $start: literal-$end: literal),* )
    ) => {
        make_header!(
            $name $size
            (
                $(
                    $field: $start-$end
                ),*
            )
            vec![0; $size]
        );
    };
}

// ethernet header
make_header!(
Ethernet 14
(
    dst: 0-47,
    src: 48-95,
    etype: 96-111
)
vec![0x0, 0x1, 0x2, 0x3, 0x4, 0x5,
     0x6, 0x7, 0x8, 0x9, 0xa, 0xb,
     0x08, 0x00]
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
vec![0x0, 0xa, 0x08, 0x00]
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
vec![
    0x45, 0x00, 0x00, 0x14, 0x00, 0x33, 0x40, 0xdd, 0x40, 0x06, 0xfa, 0xec,
    0xc0, 0xa8, 0x0, 0x1,
    0xc0, 0xa8, 0x0, 0x2,
]
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
vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x06, 0x40,
     0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
     0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x35,
]
);

// tcp header
make_header!(
TCP 20
(
    src: 0-15,
    dst: 16-31,
    seq_no: 32-63,
    ack_no: 64-95,
    data_startset: 96-99,
    res: 100-103,
    flags: 104-111,
    window: 112-127,
    checksum: 128-143,
    urgent_ptr: 144-159
)
vec![0x04, 0xd2 , 0x00, 0x50, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
     0x50, 0x02, 0x20, 0x00, 0x0d, 0x2c, 0x0, 0x0]
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
vec![0x04, 0xd2 , 0x00, 0x50, 0x0, 0x0, 0x0, 0x0]
);
