extern crate crossbeam_queue;
extern crate pnet;

use crate::packet::Packet;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::{DataLinkReceiver, DataLinkSender};

use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;

fn test_packet() -> Packet {
    crate::create_tcp_packet(
        "00:11:11:11:11:11",
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
fn create_conn(intf: &str) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let interface_names_match = |iface: &NetworkInterface| iface.name == intf;
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .clone()
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
    // Create a new channel, dealing with layer 2 packets
    let (tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };
    (tx, rx)
}

fn send_packet(tx: &mut Box<dyn DataLinkSender + 'static>, pkt: &Packet) {
    tx.send_to(pkt.to_vec().as_slice(), None);
}

fn verify_packet(rx: &mut Box<dyn DataLinkReceiver + 'static>, pkt: &Packet) {
    println!("Rx");
    match rx.next() {
        Ok(packet) => {
            println!("{:?}", packet);
            assert!(pkt.compare_with_slice(packet));
        }
        Err(e) => {
            // If an error occurs, we can handle it here
            panic!("An error occurred while reading: {}", e);
        }
    }
}

#[test]
#[ignore]
fn test_send_packet() {
    let pkt = test_packet();

    let (mut tx, _) = create_conn("feth0");
    let (_, mut rx) = create_conn("feth1");

    let tq = Arc::new(ArrayQueue::new(100));
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
    let tq = Arc::new(ArrayQueue::new(1000));
    let rq = tq.clone();
    let pair = Arc::new((Mutex::new(false), Condvar::new()));
    let pair2 = pair.clone();

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
    let pkt = test_packet();
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

    let mut pkt = test_packet();
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
        let pkt = crate::create_tcp_packet(
            "00:11:11:11:11:11",
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
        );
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
        let x: &mut crate::headers::Ethernet<Vec<u8>> = (&mut pkt["Ethernet"]).into();
        x.set_etype(i % 0xFFFF);
        tx.send(pkt.clone().to_vec()).unwrap();
        mrx.recv().unwrap();
    }
    println!("Update+Clone {} packets : {:?}", cnt, start.elapsed());
    //handle.join().unwrap();
}
