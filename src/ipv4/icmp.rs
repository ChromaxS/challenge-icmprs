use anyhow;
use bincode;
use serde::{Serialize, Deserialize};
use socket2::SockAddr;


// ICMPv4 header size //
pub const ICMPV4_PKT_BUF_SIZE: usize = 8;

pub const D_IPV4_ICMP_TYPE_ECHO_REPLY: u8 = 0x00;
pub const D_IPV4_ICMP_TYPE_UNREACHABLE: u8 = 0x03;
pub const D_IPV4_ICMP_TYPE_ECHO_REQUEST: u8 = 0x08;
pub const D_IPV4_ICMP_TYPE_EXCEEDED: u8 = 0x0B;


#[derive(Serialize, Deserialize)]
pub struct IcmpPacketHeaderV4
{
    r#type: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
}


pub fn ipv4_handle_icmp_packet(remote_sock: &SockAddr, buf: &Vec<u8>, identifier: u16, sequence: u16) -> anyhow::Result<()>
{
    // handle incoming IPv4 ICMP packet //
    let header: IcmpPacketHeaderV4 = bincode::deserialize(buf.as_slice())?;
    match header.r#type
    {
        D_IPV4_ICMP_TYPE_ECHO_REPLY => ipv4_handle_icmp_echo_reply( &remote_sock, &buf, &header, identifier, sequence ),
        _ =>
        {
            let remote_addr = remote_sock.as_socket_ipv4().unwrap();
            Err(anyhow::anyhow!( "got unexpected ICMP packet type {} code {} from: {}", header.r#type, header.code, remote_addr ))
        }
    }
}

pub fn ipv4_handle_icmp_echo_reply(remote_sock: &SockAddr, buf: &Vec<u8>, header: &IcmpPacketHeaderV4, identifier: u16, sequence: u16) -> anyhow::Result<()>
{
    let remote_addr = remote_sock.as_socket_ipv4().unwrap();
    if header.sequence != sequence
    {
        return Err(anyhow::anyhow!( "got unexpected ICMP sequence {} (was expecting {}) from: {}", header.identifier, identifier, remote_addr ));
    }
    if header.identifier != identifier
    {
        return Err(anyhow::anyhow!( "got unexpected ICMP sequence {} (was expecting {}) from: {}", header.identifier, identifier, remote_addr ));
    }
    println!( "got reply {} from {} length {}", header.sequence, remote_addr, buf.len() );
    Ok(())
}