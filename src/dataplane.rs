extern crate crossbeam_queue;
extern crate pnet_datalink;

use crossbeam_queue::ArrayQueue;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::DataPlane;
use crate::Packet;
use pnet_datalink::Channel::Ethernet;
use pnet_datalink::NetworkInterface;
use pnet_datalink::{DataLinkReceiver, DataLinkSender};

fn create_conn(intf: &str) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let interface_names_match = |iface: &NetworkInterface| iface.name == intf;
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .clone()
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
    // Create a new channel, dealing with layer 2 packets
    let (tx, rx) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    (tx, rx)
}

struct InterfaceInfo {
    interface: NetworkInterface,
    tx: Box<dyn DataLinkSender>,
}

#[derive(Debug)]
struct Payload {
    pkt: Vec<u8>,
    name: String,
}
pub struct DataPlaneImpl {
    interfaces: Vec<InterfaceInfo>,
    queue: Arc<ArrayQueue<Payload>>,
}

impl DataPlaneImpl {
    pub fn new(intfs: Vec<&str>) -> DataPlaneImpl {
        let mut interfaces: Vec<InterfaceInfo> = Vec::new();
        for intf in intfs {
            let interface_names_match = |iface: &NetworkInterface| iface.name == intf;
            let interface = match pnet_datalink::interfaces()
                .clone()
                .into_iter()
                .filter(interface_names_match)
                .next()
            {
                Some(b) => b,
                None => {
                    println!("Invalid intf {}", intf);
                    continue;
                }
            };
            // Create a new channel, dealing with layer 2 packets
            let d = pnet_datalink::Config::default();
            let (tx, _) = match pnet_datalink::channel(&interface, d) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unhandled channel type"),
                Err(e) => panic!(
                    "An error occurred when creating the datalink channel: {}",
                    e
                ),
            };
            interfaces.push(InterfaceInfo { interface, tx });
            thread::sleep(Duration::from_millis(100));
        }
        let queue: Arc<ArrayQueue<Payload>> = Arc::new(ArrayQueue::new(1000));
        DataPlaneImpl { interfaces, queue }
    }
    pub fn run(&self) {
        for ii in &self.interfaces {
            let d = pnet_datalink::Config::default();
            let (_tx, mut rx) = match pnet_datalink::channel(&ii.interface, d) {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => panic!("Unhandled channel type"),
                Err(e) => panic!(
                    "An error occurred when creating the datalink channel: {}",
                    e
                ),
            };
            let tq = self.queue.clone();
            let ifs = ii.interface.name.clone();
            thread::spawn(move || {
                loop {
                    match rx.next() {
                        Ok(packet) => {
                            let payload = Payload {
                                pkt: Vec::from(packet),
                                name: ifs.clone(),
                            };
                            tq.push(payload).unwrap();
                            // println!("{} {}", ifs, tq.len());
                        }
                        Err(e) => {
                            // If an error occurs, we can handle it here
                            panic!("An error occurred while reading: {}", e);
                        }
                    }
                }
            });
        }
    }
    pub fn send(&mut self, intf: &str, pkt: &Packet) {
        for interface in &mut self.interfaces {
            if interface.interface.name == intf {
                interface.tx.send_to(pkt.to_vec().as_slice(), None);
            }
        }
    }
    fn pull(&self) -> Vec<Payload> {
        let mut pkts = Vec::new();
        while !self.queue.is_empty() {
            pkts.push(self.queue.pop().unwrap());
        }
        pkts
    }
    #[inline]
    fn poll(&self, timeout: u64) -> Result<Vec<Payload>, u64> {
        // thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        loop {
            let pkts = self.pull();
            if pkts.len() != 0 {
                return Ok(pkts);
            }
            thread::sleep(Duration::from_millis(1));
            if (Instant::now() - start) > Duration::from_secs(timeout) {
                break;
            }
        }
        Err(0)
    }
    pub fn verify_packet(&self, intf: &str, pkt: &Packet) {
        let pkts = match self.poll(1) {
            Ok(pkts) => pkts,
            Err(_) => Vec::new(),
        };
        if pkts.len() != 1 {
            panic!("Received {} packets when expecting 1 packet", pkts.len());
        }
        if intf != pkts[0].name {
            panic!("Expected packet on {}, received on {}", intf, pkts[0].name);
        }
        assert!(pkt.compare_with_slice(pkts[0].pkt.as_slice()));
    }
    pub fn verify_packet_on_each_port(&self, intf: Vec<&str>, pkt: &Packet) {
        let pkts = match self.poll(1) {
            Ok(pkts) => pkts,
            Err(_) => Vec::new(),
        };
        if pkts.len() != intf.len() {
            panic!(
                "Received {} packets when expecting {} packet",
                pkts.len(),
                intf.len()
            );
        }
        for payload in pkts {
            if intf.iter().find(|&&x| x == payload.name) == None {
                panic!("Did not receive expected packet on {}", payload.name);
            }
            assert!(pkt.compare_with_slice(payload.pkt.as_slice()));
        }
    }
}

impl DataPlane for DataPlaneImpl {
    fn run(&self) {
        self.run();
    }
    fn send(&mut self, intf: &str, pkt: &Packet) {
        self.send(intf, pkt);
    }
    fn verify_packet(&self, intf: &str, pkt: &Packet) {
        self.verify_packet(intf, pkt);
    }
    fn verify_packet_on_each_port(&self, intf: Vec<&str>, pkt: &Packet) {
        self.verify_packet_on_each_port(intf, pkt);
    }
}

#[inline]
pub fn dataplane(interfaces: Vec<&str>) -> Box<dyn DataPlane> {
    Box::from(DataPlaneImpl::new(interfaces))
}

fn send_packet(tx: &mut Box<dyn DataLinkSender + 'static>, pkt: &Packet) {
    tx.send_to(pkt.to_vec().as_slice(), None);
}

fn sample_packet() -> Packet {
    Packet::create_tcp_packet(
        "66:65:74:68:00:01",
        "00:06:07:08:09:0a",
        false,
        10,
        3,
        5,
        "10.10.10.1",
        "11.11.11.1",
        0,
        64,
        115,
        0,
        Vec::new(),
        8888,
        9090,
        100,
        101,
        5,
        0,
        2,
        0,
        0,
        false,
        100,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc, Condvar, Mutex};
    #[test]
    #[ignore]
    fn test_send_packet() {
        let pkt = sample_packet();

        let (mut tx, _) = create_conn("feth0");
        let (_, mut rx) = create_conn("feth1");

        let tq = Arc::new(crossbeam_queue::ArrayQueue::new(100));
        let rq = tq.clone();
        let pair = Arc::new((Mutex::new(false), Condvar::new()));
        let pair2 = pair.clone();

        let _handle = thread::spawn(move || {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        println!(" rx 1 {:?}", packet);
                        let &(ref lock, ref cvar) = &*pair2;

                        tq.push(Vec::from(packet)).unwrap();
                        let mut started = lock.lock().unwrap();
                        *started = true;
                        cvar.notify_one();
                        println!(" rx 2 {:?}", packet);
                        // assert!(epkt.compare_with_slice(packet));
                    }
                    Err(e) => {
                        // If an error occurs, we can handle it here
                        panic!("An error occurred while reading: {}", e);
                    }
                }
            }
        });

        thread::sleep(Duration::from_millis(100));
        let start = Instant::now();
        let cnt = 100;
        for _ in 0..cnt {
            let &(ref lock, ref cvar) = &*pair;
            let mut started = lock.lock().unwrap();
            send_packet(&mut tx, &pkt);
            while !*started {
                started = cvar.wait(started).unwrap();
            }
            let p: Vec<u8> = rq.pop().unwrap();
            // let p = mrx.recv().unwrap();
            assert!(pkt.compare_with_slice(p.as_slice()));
            *started = false;
        }
        let duration = start.elapsed();
        println!("Time elapsed for {} packets is: {:?}", cnt, duration);

        // _handle.join().unwrap();
    }

    #[test]
    // Simulate multi port Rx and pipe to a single a reciever queue
    fn packet_mc_test() {
        let (tx, rx): (mpsc::SyncSender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) = mpsc::sync_channel(0);
        let tq = Arc::new(crossbeam_queue::ArrayQueue::new(1000));
        let rq = tq.clone();
        // let pair = Arc::new((Mutex::new(false), Condvar::new()));
        // let pair2 = pair.clone();

        // ping packets on different channels
        thread::spawn(move || loop {
            match rx.recv() {
                Ok(pkt) => {
                    //let &(ref lock, ref cvar) = &*pair2;
                    //let mut started = lock.lock().unwrap();
                    tq.push(Vec::from(pkt)).unwrap();
                    //*started = true;
                    //cvar.notify_one();
                }
                Err(_) => break,
            };
        });

        let tcount = 10;
        let pkt = sample_packet();
        for _ in 0..tcount {
            let p3 = pkt.clone();
            let t3 = tx.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(1));
                for _ in 0..100 {
                    t3.send(p3.to_vec()).unwrap();
                }
            });
        }

        let rc = thread::spawn(move || {
            let mut count = 0;
            while count != tcount * 100 {
                //let &(ref lock, ref cvar) = &*pair;
                //let mut started = lock.lock().unwrap();
                //while !*started {
                //    started = cvar.wait(started).unwrap();
                //}
                while !rq.is_empty() {
                    let p: Vec<u8> = rq.pop().unwrap();
                    assert!(pkt.compare_with_slice(p.as_slice()));
                    count += 1;
                }
                //*started = false;
            }
        });
        rc.join().unwrap();
    }

    #[test]
    fn packet_gen_test() {
        let (tx, rx): (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) = mpsc::channel();
        let (mtx, mrx): (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) = mpsc::channel();

        // ping packets on different channels
        thread::spawn(move || loop {
            match rx.recv_timeout(Duration::from_millis(10)) {
                Ok(pkt) => mtx.send(Vec::from(pkt)).unwrap(),
                Err(_) => break,
            };
        });

        let mut pkt = sample_packet();
        // same packet in every iteration
        let start = Instant::now();
        let cnt = 100000;
        for _ in 0..cnt {
            tx.send(pkt.to_vec()).unwrap();
            mrx.recv().unwrap();
        }
        println!("Same {} packets         : {:?}", cnt, start.elapsed());

        // new packet in every iteration
        let start = Instant::now();
        for _ in 0..cnt {
            let pkt = sample_packet();
            tx.send(pkt.to_vec()).unwrap();
            mrx.recv().unwrap();
        }
        println!("New {} packets          : {:?}", cnt, start.elapsed());

        // clone packet in each iteration
        let start = Instant::now();
        for _ in 0..cnt {
            tx.send(pkt.clone().to_vec()).unwrap();
            mrx.recv().unwrap();
        }
        println!("Clone {} packets        : {:?}", cnt, start.elapsed());

        // update packet and then clone in each iteration
        let start = Instant::now();
        for i in 0..cnt {
            let x: &mut crate::headers::Ethernet = (&mut pkt["Ethernet"]).into();
            x.set_etype(i % 0xFFFF);
            tx.send(pkt.clone().to_vec()).unwrap();
            mrx.recv().unwrap();
        }
        println!("Update+Clone {} packets : {:?}", cnt, start.elapsed());
        //handle.join().unwrap();
    }

    #[test]
    #[ignore]
    fn dp_test() {
        let intfs = vec!["feth0", "feth1"];
        let mut dp = dataplane(intfs);
        dp.run();

        let cnt = 100;
        for _ in 0..cnt {
            let pkt = sample_packet();
            &mut dp.send("feth1", &pkt);
            // dp.verify_packet("feth0", &pkt)
            dp.verify_packet_on_each_port(vec!["feth1", "feth0"], &pkt);
        }
    }
}
