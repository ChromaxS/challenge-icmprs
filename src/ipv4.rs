use anyhow;
use serde::{Deserialize, Serialize};
use socket2::SockAddr;

pub mod icmp;


pub const IPV4_PKT_BUF_SIZE: usize = 20;
pub const IPV4_PKT_OCTET_SIZE: usize = 4;

pub const D_IP_IP_VERSION_4: u8 = 0x04;

pub const D_IP_IP_TYPE_ICMP: u8 = 0x01;


#[derive(Serialize, Deserialize, Debug)]
pub struct Ipv4PacketHeaderV4
{
    pub header_length_and_version: u8,
    pub differentiated_services: u8,
    pub length: u16,
    pub identification: u16,
    pub flags_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source_ip: u32,
    pub destination_ip: u32,
}


fn ipv4_compute_checksum(buf: &Vec<u8>) -> anyhow::Result<u16>
{
    let mut sum: u32 = 0;

    // deal with non-word aligned length //
    let mut length = buf.len();
    if length > 0 && length % 2 > 0
    {
        sum = sum + u32::from(buf[length as usize - 1]);
        length = length - 1;
    }

    if length > 0
    {
        // add all the words into the sum and wrap //
        for word_index in (0..length - 1).step_by(2)
        {
            let part = (u16::from(buf[word_index]) << 8) + u16::from(buf[word_index + 1]);
            sum = sum.wrapping_add(u32::from(part));
        }
    }

    // fold sum to 16 bits: add carry to result //
    while (sum >> 16) > 0
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // return (and handle one's compliment) //
    Ok(!sum as u16)
}

pub(crate) fn ipv4_handle_packet(remote_sock: &SockAddr, buf: &Vec<u8>, program_state: &mut crate::IcmpProgramState) -> anyhow::Result<()>
{
    // handle incoming ipv4 packets //
    let remote_addr = remote_sock.as_socket_ipv4().unwrap();
    let ip: Ipv4PacketHeaderV4 = bincode::deserialize(buf.as_slice())?;
    // the header length and version are 4 bits each, so get the high/low bits //
    let ip_version = (ip.header_length_and_version >> 4) & 0x0F;
    if ip_version != D_IP_IP_VERSION_4
    {
        return Err(anyhow::anyhow!( "Invalid IPv4 header version, {} != {}, from: {}", ip_version, D_IP_IP_VERSION_4, remote_addr ));
    }
    let data_offset = (ip.header_length_and_version & 0x0F) * IPV4_PKT_OCTET_SIZE as u8;
    if data_offset != IPV4_PKT_BUF_SIZE as u8
    {
        return Err(anyhow::anyhow!( "Invalid IPv4 header size, {} != {}, from: {}", data_offset, IPV4_PKT_BUF_SIZE, remote_addr ));
    }
    let (_, data) = buf.split_at(data_offset.into());
    log::debug!( "got ipv4 packet: {:?} (data_offset={}, data_len={})", &ip, data_offset.to_be(), ip.length.to_be() );

    match ip.protocol
    {
        D_IP_IP_TYPE_ICMP => icmp::ipv4_handle_icmp_packet( remote_sock, &ip, &data.to_vec(), program_state ),
        _ => Err(anyhow::anyhow!( "unhandled protocol type: {}", ip.protocol )),
    }
}