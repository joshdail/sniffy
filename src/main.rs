mod capture;
mod core;
mod packet;
mod ui;

use crate::core::capture_loop::initialize_capture;
use crate::core::signal::setup_ctrlc_handler;
use crate::core::summary::print_packet_summary;
use crate::packet::{parse_packet, PacketType, PacketInfo};

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::{thread, time, process};
use pcap;

fn main() {
    let running = Arc::new(AtomicBool::new(true));
    setup_ctrlc_handler(Arc::clone(&running));

    let mut cap = match initialize_capture() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("{}", err);
            return;
        }
    };

    let packet_counts = Arc::new(Mutex::new(HashMap::<PacketType, usize>::new()));

    println!("Capturing on interface... Press Ctrl+C to stop and see summary");

    while running.load(Ordering::SeqCst) {
        match cap.next_packet() {
            Ok(packet) => {
                match parse_packet(&packet.data) {
                    Ok(packet_info) => {
                        // Print summary line for this packet:
                        print_packet_info(&packet_info);

                        // Update counts
                        let mut counts = packet_counts.lock().unwrap();
                        *counts.entry(packet_info.packet_type).or_insert(0) += 1;
                    }
                    Err(err) => eprintln!("Error parsing packet: {}", err),
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                thread::sleep(time::Duration::from_millis(10));
            }
            Err(err) => {
                eprintln!("Error reading packet: {}", err);
                thread::sleep(time::Duration::from_millis(10));
            }
        }
    }

    print_packet_summary(Arc::clone(&packet_counts));

    process::exit(0);
}

fn print_packet_info(info: &PacketInfo) {
    // MAC addresses formatted as XX:XX:XX:XX:XX:XX or "??"
    let src_mac = info.src_mac
        .map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]))
        .unwrap_or_else(|| "??".into());
    let dst_mac = info.dst_mac
        .map(|m| format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5]))
        .unwrap_or_else(|| "??".into());

    print!("Ethernet frame: Src MAC {} Dst MAC {} ", src_mac, dst_mac);

    match info.packet_type {
        PacketType::IPv4 | PacketType::TCP | PacketType::UDP | PacketType::DNS => {
            print!("IPv4 src {} dst {} ", info.src_ip.as_deref().unwrap_or("??"), info.dst_ip.as_deref().unwrap_or("??"));
        }
        PacketType::IPv6 => {
            print!("IPv6 src {} dst {} ", info.src_ip.as_deref().unwrap_or("??"), info.dst_ip.as_deref().unwrap_or("??"));
        }
        _ => {}
    }

    match info.packet_type {
        PacketType::TCP => {
            print!("TCP src_port {} dst_port {} flags 0x{:02x} ", 
                info.src_port.unwrap_or(0), info.dst_port.unwrap_or(0), info.tcp_flags.unwrap_or(0));
        }
        PacketType::UDP => {
            print!("UDP src_port {} dst_port {} ", 
                info.src_port.unwrap_or(0), info.dst_port.unwrap_or(0));
        }
        PacketType::DNS => {
            print!("DNS src_port {} dst_port {} queries: ", 
                info.src_port.unwrap_or(0), info.dst_port.unwrap_or(0));
            if let Some(queries) = &info.dns_queries {
                if queries.is_empty() {
                    print!("(no queries)");
                } else {
                    print!("{}", queries.join(", "));
                }
            } else {
                print!("(unable to parse queries)");
            }
            print!(" ");
        }
        _ => {}
    }

    println!("Type {}", info.packet_type);
}
