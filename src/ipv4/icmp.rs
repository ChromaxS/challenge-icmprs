/*

icmprs - An asynchronous ICMP ping implementation in Rust.
author: Christopher Eades 2023-10-07
license: CC0 1.0 Universal https://creativecommons.org/publicdomain/zero/1.0/

*/

use anyhow;
use bincode;
use serde::{Deserialize, Serialize};
use socket2::SockAddr;
use std::net::IpAddr;

// ICMPv4 header size //
pub const ICMPV4_PKT_BUF_SIZE: usize = 8;

pub const D_IPV4_ICMP_TYPE_ECHO_REPLY: u8 = 0x00;
pub const D_IPV4_ICMP_TYPE_UNREACHABLE: u8 = 0x03;
pub const D_IPV4_ICMP_TYPE_ECHO_REQUEST: u8 = 0x08;
pub const D_IPV4_ICMP_TYPE_EXCEEDED: u8 = 0x0B;

#[derive(Serialize, Deserialize, Debug)]
pub struct IcmpPacketHeaderV4 {
    pub r#type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
}

pub fn ipv4_icmp_create_echo_request(
    identifier: u16,
    sequence: u16,
    data_size: usize,
) -> anyhow::Result<Vec<u8>> {
    // create the icmp echo request //
    let mut buf: Vec<u8> = vec![];
    buf.resize(ICMPV4_PKT_BUF_SIZE + data_size, 0x00);

    // write header //
    let header = IcmpPacketHeaderV4 {
        r#type: D_IPV4_ICMP_TYPE_ECHO_REQUEST,
        code: 0,
        checksum: 0,
        identifier,
        sequence,
    };
    bincode::serialize_into(&mut buf[0..], &header)?;

    // write the data: ABCDEF... ABCDEF... //
    for n in 0..data_size - 1 {
        buf[ICMPV4_PKT_BUF_SIZE + n] = ((n % 26) + 65) as u8;
    }

    // fixup the checksum now (bit-bang into the array... this is mostly sadness and a micro-optimization at the same time!) //
    let checksum = crate::ipv4::ipv4_compute_checksum(&buf)?;
    buf[2] = (checksum >> 8) as u8;
    buf[3] = (checksum & 0xff) as u8;
    Ok(buf)
}

pub(crate) fn ipv4_handle_icmp_packet(
    remote_sock: &SockAddr,
    ip: &crate::ipv4::Ipv4PacketHeaderV4,
    buf: &Vec<u8>,
    program_state: &mut crate::IcmpProgramState,
) -> anyhow::Result<()> {
    // handle incoming IPv4 ICMP packet //
    let icmp: IcmpPacketHeaderV4 = bincode::deserialize(buf.as_slice())?;
    log::debug!("got icmp packet: {:?}", &icmp);
    match icmp.r#type {
        D_IPV4_ICMP_TYPE_ECHO_REPLY => {
            ipv4_handle_icmp_echo_reply(remote_sock, ip, buf, &icmp, program_state)
        }
        D_IPV4_ICMP_TYPE_UNREACHABLE | D_IPV4_ICMP_TYPE_EXCEEDED => {
            ipv4_handle_icmp_error(remote_sock, ip, buf, &icmp, program_state)
        }
        _ => {
            let remote_addr = remote_sock.as_socket_ipv4().unwrap();
            Err(anyhow::anyhow!(
                "got unexpected ICMP packet type {} code {} from: {}",
                icmp.r#type,
                icmp.code,
                remote_addr
            ))
        }
    }
}

pub(crate) fn ipv4_handle_icmp_echo_reply(
    remote_sock: &SockAddr,
    ip: &crate::ipv4::Ipv4PacketHeaderV4,
    buf: &Vec<u8>,
    icmp: &IcmpPacketHeaderV4,
    program_state: &mut crate::IcmpProgramState,
) -> anyhow::Result<()> {
    let remote_addr = remote_sock.as_socket_ipv4().unwrap();
    if icmp.identifier != program_state.identifier {
        return Err(anyhow::anyhow!(
            "got unexpected ICMP echo identifier {} (was expecting {}) sequence={} from: {}",
            icmp.identifier,
            program_state.identifier,
            icmp.sequence,
            remote_addr
        ));
    }
    match program_state.remove_sequence(icmp.sequence) {
        Some(original_instant) => {
            let data_bytes = buf.len() - ICMPV4_PKT_BUF_SIZE;
            let remote_ip = IpAddr::V4(remote_sock.as_socket_ipv4().unwrap().ip().to_owned());
            program_state.output_ping(
                data_bytes,
                &program_state.host_addr.ip(),
                &remote_ip,
                original_instant,
                icmp.sequence,
                ip.ttl,
            );
            program_state.responded_successfully += 1;
        }
        _ => log::error!(
            "got unexpected ICMP echo sequence {} from: {}",
            icmp.sequence,
            remote_addr
        ),
    }

    Ok(())
}

pub(crate) fn ipv4_handle_icmp_error(
    remote_sock: &SockAddr,
    ip: &crate::ipv4::Ipv4PacketHeaderV4,
    buf: &[u8],
    icmp: &IcmpPacketHeaderV4,
    program_state: &mut crate::IcmpProgramState,
) -> anyhow::Result<()> {
    // see if there's an encapsulated ICMP packet in this frame (unreachable/exceeded are encapsulated by an upstream gateway/router) //

    // encapsulated ip packet //
    let (_, buf_ip_encapsulated) = buf.split_at(ICMPV4_PKT_BUF_SIZE);
    let ip_encapsulated: crate::ipv4::Ipv4PacketHeaderV4 =
        bincode::deserialize(buf_ip_encapsulated)?;
    log::debug!("got ip encapsulated packet: {:?}", &ip_encapsulated);
    let ip_encapsulated_version = (ip_encapsulated.header_length_and_version >> 4) & 0x0F;
    let data_encapsulated_offset =
        (ip_encapsulated.header_length_and_version & 0x0F) * crate::ipv4::IPV4_PKT_OCTET_SIZE as u8;
    if ip_encapsulated_version != crate::ipv4::D_IP_IP_VERSION_4
        && data_encapsulated_offset != crate::ipv4::IPV4_PKT_BUF_SIZE as u8
    {
        return Err(anyhow::anyhow!(
            "Invalid IPv4 encapsulated in ICMP error packet!"
        ));
    }

    // encapsulated icmp packet //
    let (_, buf_icmp_encapsulated) = buf_ip_encapsulated.split_at(data_encapsulated_offset.into());
    let icmp_encapsulated: IcmpPacketHeaderV4 = bincode::deserialize(buf_icmp_encapsulated)?;
    log::debug!("got icmp encapsulated packet: {:?}", &icmp_encapsulated);

    // only regular output should be handled here... CSV just times out in the main loop //
    let remote_ip = IpAddr::V4(remote_sock.as_socket_ipv4().unwrap().ip().to_owned());
    if icmp_encapsulated.identifier == program_state.identifier {
        if !matches!(program_state.output, crate::cli::OutputMode::CSV) {
            // if regular output is being used then icmp errors are reported so we can dequeue them if we're tracking the sequence... otherwise let it timeout //

            // dequeue //
            let original_instant = program_state.remove_sequence(icmp_encapsulated.sequence);

            // report on the encapsulated packet //
            match icmp.r#type {
                D_IPV4_ICMP_TYPE_UNREACHABLE => program_state.output_error(
                    &program_state.host_addr.ip(),
                    &remote_ip,
                    original_instant,
                    icmp_encapsulated.sequence,
                    ip.ttl,
                    "host unreachable".to_owned(),
                ),
                D_IPV4_ICMP_TYPE_EXCEEDED => program_state.output_error(
                    &program_state.host_addr.ip(),
                    &remote_ip,
                    original_instant,
                    icmp_encapsulated.sequence,
                    ip.ttl,
                    "time to live exceeded".to_owned(),
                ),
                _ => log::error!(
                    "got unexpected ICMP echo identifier {} sequence {} from: {}",
                    icmp_encapsulated.identifier,
                    icmp_encapsulated.sequence,
                    remote_ip
                ),
            };
        }
    } else {
        log::error!(
            "got unexpected ICMP echo identifier {} (was expecting {}) sequence={} from: {}",
            icmp.identifier,
            program_state.identifier,
            icmp.sequence,
            remote_ip
        );
    }
    Ok(())
}
