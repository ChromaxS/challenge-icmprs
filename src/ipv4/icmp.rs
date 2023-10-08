/*

icmprs - An asynchronouse ICMP ping implementation in Rust.
author: Christopher Eades 2023-10-07
license: CC0 1.0 Universal https://creativecommons.org/publicdomain/zero/1.0/

*/


use anyhow;
use bincode;
use serde::{Serialize, Deserialize};
use socket2::SockAddr;
use std::time::Instant;


// ICMPv4 header size //
pub const ICMPV4_PKT_BUF_SIZE: usize = 8;

pub const D_IPV4_ICMP_TYPE_ECHO_REPLY: u8 = 0x00;
pub const D_IPV4_ICMP_TYPE_UNREACHABLE: u8 = 0x03;
pub const D_IPV4_ICMP_TYPE_ECHO_REQUEST: u8 = 0x08;
pub const D_IPV4_ICMP_TYPE_EXCEEDED: u8 = 0x0B;


#[derive(Serialize, Deserialize, Debug)]
pub struct IcmpPacketHeaderV4
{
    pub r#type: u8,
    pub code: u8,
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
}


pub fn ipv4_icmp_create_echo_request(identifier: u16, sequence: u16, data_size: usize) -> anyhow::Result<Vec<u8>>
{
    // create the icmp echo request //
    let mut buf: Vec<u8> = vec![];
    buf.resize( ICMPV4_PKT_BUF_SIZE + data_size, 0x00 );

    // write header //
    let header = IcmpPacketHeaderV4
    {
        r#type: D_IPV4_ICMP_TYPE_ECHO_REQUEST,
        code: 0,
        checksum: 0,
        identifier,
        sequence,
    };
    bincode::serialize_into( &mut buf[0..], &header )?;

    // write the data: ABCDEF... ABCDEF... //
    for n in 0..data_size - 1
    {
        buf[ICMPV4_PKT_BUF_SIZE + n as usize] = ((n % 26) + 65) as u8;
    }

    // fixup the checksum now (bit-bang into the array... this is mostly sadness and a micro-optimization at the same time!) //
    let checksum = crate::ipv4::ipv4_compute_checksum(&buf)?;
    buf[2] = (checksum >> 8) as u8;
    buf[3] = (checksum & 0xff) as u8;
    Ok(buf)
}


pub(crate) fn ipv4_handle_icmp_packet(remote_sock: &SockAddr, ip: &crate::ipv4::Ipv4PacketHeaderV4, buf: &Vec<u8>, program_state: &mut crate::IcmpProgramState) -> anyhow::Result<()>
{
    // handle incoming IPv4 ICMP packet //
    let icmp: IcmpPacketHeaderV4 = bincode::deserialize(buf.as_slice())?;
    log::debug!( "got icmp packet: {:?}", &icmp );
    match icmp.r#type
    {
        D_IPV4_ICMP_TYPE_ECHO_REPLY => ipv4_handle_icmp_echo_reply( &remote_sock, ip, &buf, &icmp, program_state ),
        D_IPV4_ICMP_TYPE_UNREACHABLE | D_IPV4_ICMP_TYPE_EXCEEDED => ipv4_handle_icmp_error( &remote_sock, ip, &buf, &icmp, program_state ),
        _ =>
        {
            let remote_addr = remote_sock.as_socket_ipv4().unwrap();
            Err(anyhow::anyhow!( "got unexpected ICMP packet type {} code {} from: {}", icmp.r#type, icmp.code, remote_addr ))
        },
    }
}

pub(crate) fn ipv4_handle_icmp_echo_reply(
  remote_sock: &SockAddr,
  ip: &crate::ipv4::Ipv4PacketHeaderV4,
  buf: &Vec<u8>,
  icmp: &IcmpPacketHeaderV4,
  program_state: &mut crate::IcmpProgramState) -> anyhow::Result<()>
{
    let remote_addr = remote_sock.as_socket_ipv4().unwrap();
    if icmp.identifier != program_state.identifier
    {
        return Err(anyhow::anyhow!( "got unexpected ICMP echo identifier {} (was expecting {}) sequence={} from: {}", icmp.identifier, program_state.identifier, icmp.sequence, remote_addr ));
    }
    let now = Instant::now();
    let mut found_sequence = false;
    // this isn't the most efficient but we're not working with a large list of packets and even then so, it'd have to be hundreds of thousands or so //
    // to be really bad //
    program_state.sent.retain_mut(|sent|
    {
        // see if this is the packet we're looking for //
        if sent.sequence != icmp.sequence
        {
            return true;
        }

        found_sequence = true;
        if !program_state.quiet
        {
            match program_state.output
            {
                crate::cli::OutputMode::Default | crate::cli::OutputMode::Regular =>
                {
                    // regular output //
                    match icmp.r#type
                    {
                        D_IPV4_ICMP_TYPE_ECHO_REPLY =>
                        {
                            // normal reply //
                            let request_millis = (now - sent.instant).as_secs_f64() * 1000.0;
                            let data_bytes = buf.len() - ICMPV4_PKT_BUF_SIZE;
                            println!( "{} bytes from {}: icmp_seq={} ttl={}: {:.3} ms", data_bytes, remote_addr.ip(), sent.sequence, ip.ttl, request_millis );
                        },
                        _ => println!( "Reply from {}: icmp_seq={}: unknown code received", remote_addr.ip(), sent.sequence ),
                    }
                },
                crate::cli::OutputMode::CSV =>
                {
                    // REQUIREMENT: IPv4,icmp_sequence_number,elapsed_time_in_microseconds
                    let elapsed_in_microseconds = (now - program_state.started).as_micros();
                    println!( "{},{},{}", remote_addr.ip(), sent.sequence, elapsed_in_microseconds );
                },
            }
        }

        if icmp.r#type == D_IPV4_ICMP_TYPE_ECHO_REPLY
        {
            program_state.responded_successfully = program_state.responded_successfully + 1;
        }
        return false;
    });
    if !found_sequence
    {
        log::error!( "got unexpected ICMP echo sequence {} from: {}", icmp.sequence, remote_addr );
    }
    Ok(())
}

pub(crate) fn ipv4_handle_icmp_error(
    remote_sock: &SockAddr,
    ip: &crate::ipv4::Ipv4PacketHeaderV4,
    buf: &Vec<u8>,
    icmp: &IcmpPacketHeaderV4,
    program_state: &mut crate::IcmpProgramState) -> anyhow::Result<()>
{
    // see if there's an encapsulated ICMP packet in this frame (unreachable/exceeded are encapsulated by an upstream gateway/router) //

    // encapsulated ip packet //
    let (_, buf_ip_encapsulated) = buf.split_at(ICMPV4_PKT_BUF_SIZE);
    let ip_encapsulated: crate::ipv4::Ipv4PacketHeaderV4 = bincode::deserialize(buf_ip_encapsulated)?;
    log::debug!( "got ip encapsulated packet: {:?}", &ip_encapsulated );
    let ip_encapsulated_version = (ip_encapsulated.header_length_and_version >> 4) & 0x0F;
    let data_encapsulated_offset = (ip_encapsulated.header_length_and_version & 0x0F) * crate::ipv4::IPV4_PKT_OCTET_SIZE as u8;
    if ip_encapsulated_version != crate::ipv4::D_IP_IP_VERSION_4 && data_encapsulated_offset != crate::ipv4::IPV4_PKT_BUF_SIZE as u8
    {
        return Err(anyhow::anyhow!("Invalid IPv4 encapsulated in ICMP error packet!"));
    }

    // encapsulated icmp packet //
    let (_, buf_icmp_encapsulated) = buf_ip_encapsulated.split_at(data_encapsulated_offset.into());
    let icmp_encapsulated: IcmpPacketHeaderV4 = bincode::deserialize(buf_icmp_encapsulated)?;
    log::debug!( "got icmp encapsulated packet: {:?}", &icmp_encapsulated );
    let remote_addr = remote_sock.as_socket_ipv4().unwrap();
    if icmp_encapsulated.identifier == program_state.identifier
    {
        // report on the encapsulated packet //
        match icmp.r#type
        {
            D_IPV4_ICMP_TYPE_UNREACHABLE =>
            {
                if !program_state.quiet && (matches!( program_state.output, crate::cli::OutputMode::Default ) || matches!( program_state.output, crate::cli::OutputMode::Regular ))
                {
                    println!( "Reply from {}: icmp_seq={} ttl={}: host unreachable", remote_addr.ip(), icmp_encapsulated.sequence, ip.ttl );
                }
            },
            D_IPV4_ICMP_TYPE_EXCEEDED =>
            {
                if !program_state.quiet && (matches!( program_state.output, crate::cli::OutputMode::Default ) || matches!( program_state.output, crate::cli::OutputMode::Regular ))
                {
                    println!( "Reply from {}: icmp_seq={} ttl={}: time to live exceeded", remote_addr.ip(), icmp_encapsulated.sequence, ip.ttl );
                }
            },
            _ => log::error!( "got unexpected ICMP echo identifier {} sequence {} from: {}", icmp_encapsulated.identifier, icmp_encapsulated.sequence, remote_addr ),
        }

        // dequeue if we're tracking this //
        program_state.sent.retain_mut(|sent|
        {
            // see if this is the packet we're looking for //
            if sent.sequence != icmp.sequence
            {
                return true;
            }

            log::debug!( "dequeued sent tracking sequence ID: {}", sent.sequence );

            return false;
        });
    }else
    {
        log::error!( "got unexpected ICMP echo identifier {} (was expecting {}) sequence={} from: {}", icmp.identifier, program_state.identifier, icmp.sequence, remote_addr );
    }
    Ok(())
}