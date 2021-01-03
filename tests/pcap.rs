use std::{
    fs::OpenOptions,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn pcap_write(packets: Vec<&[u8]>) {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    let tv_sec = since_the_epoch.as_secs() as u32;
    let tv_usec = since_the_epoch.subsec_millis() as u32;
    let mut temp = OpenOptions::new()
        .create(true)
        .write(true)
        .append(false)
        .open("temp.pcap")
        .unwrap();
    let global_header = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 0x2, 0x0, 0x4, 0x0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0,
        0, 0,
    ];
    temp.write_all(global_header.as_slice()).unwrap();

    for packet in packets {
        let plen = packet.len() as u32;
        let mut pcap_header = Vec::new();
        pcap_header.extend_from_slice(&tv_sec.to_le_bytes());
        pcap_header.extend_from_slice(&tv_usec.to_le_bytes());
        pcap_header.extend_from_slice(&plen.to_le_bytes());
        pcap_header.extend_from_slice(&plen.to_le_bytes());

        temp.write_all(pcap_header.as_slice()).unwrap();
        temp.write_all(packet).unwrap();
    }
}
