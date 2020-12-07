Rust based Scapy alternative

Introduction
============
Rscapy is a rust based alternative to the popular python Scapy packet library. It tries to provide a scapy like API interface to define new headers and create layers of headers into a packet.

make_header
===========
The core of the library is the make_header macro which provides a flexible way to create new headers.<br>
Describe a new header in the below format.
```
make_header!(

<header_name> <length in bytes>

<field_name1> <start_bit> - <end_bit>,

<field_name2> <start_bit> - <end_bit>,
)
```

Add a header
------------
Add a new header by using the *make_header* macro.

```rust
#[macro_use]
extern crate rscapy;

use rscapy::headers::*;

make_header!(
Vlan 4
(
    pcp: 0-2,
    cfi: 3-3,
    vid: 4-15,
    etype: 16-31
)
);
```

Create the header
-----------------
Create the vlan header in 2 ways.
1. Pass a data buffer as an argument
```rust
let data = [0x00, 0x0a, 0x08, 0x10];
let vlan = Vlan(data);
vlan.octets(); // get the vlan header as bytes
vlan.show();   // display the vlan header
let vlan_new = vlan.clone(); // clone the packet
```
2. Create empty header and fill in data
```rust
let data = [0, 0, 0, 0];
let vlan = Vlan(data);
vlan.set_pcp(0);
vlan.set_cfi(0);
vlan.set_vlan(10);
vlan.set_etype(0x800);
vlan.show()
```
```text
Output of show:
Bytes: 00 0a 08 00
#### Vlan             Size   Data
-------------------------------------------
pcp                 :    3 : 00
cfi                 :    1 : 00
vid                 :   12 : 00 10
etype               :   16 : 08 00
```