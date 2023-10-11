use socket2::{SockAddr, Socket, Domain, Type, Protocol};
use std::fmt;
use std::os::fd::RawFd;
use std::os::unix::io::AsRawFd;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};

#[derive(Debug)]
pub struct IcmpSocketErrorFormat
{
    pub error: String,
}

impl std::error::Error for IcmpSocketErrorFormat {}

impl fmt::Display for IcmpSocketErrorFormat
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!( f, "Invalid format specified: {}", &self.error )
    }
}


pub struct IcmpSocket
{
    async_fd: AsyncFd<RawFd>,
    inner: Socket,
    remote: SockAddr,
}


impl IcmpSocket
{
    pub fn bind(addr: &SockAddr) -> Result<Self, std::io::Error>
    {
        // creates the socket and binds to the specified address //
        let socket = if addr.is_ipv4()
        {
            Socket::new_raw( Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4) )
              .map_err(|e| std::io::Error::new( std::io::ErrorKind::Other, e ))
        }else if addr.is_ipv6()
        {
            // TODO: v6... //
            unimplemented!("does not support IPv6!");
        }else
        {
            let e = IcmpSocketErrorFormat { error: "specified addr is neither IPv4 or IPv6!".to_string() };
            return Err(std::io::Error::new( std::io::ErrorKind::Other, e ));
        }?; 

        // allow us to do non-blocking I/O //
        socket.set_nonblocking(true)?;

        // get the AsyncFd<RawFd> for async operations like readable //
        let async_fd = match AsyncFd::new(socket.as_raw_fd())
        {
            Ok(async_fd) => async_fd,
            Err(e) => return Err(std::io::Error::new( std::io::ErrorKind::Other, e )),
        };

        // construct the IcmpSocket structure now //
        let icmp_socket = Self
        {
            async_fd,
            inner: socket,
            remote: addr.to_owned(),
        };

        // finally bind //
        // FIXME: does not bind on WSL
        // icmp_socket.inner.bind(&icmp_socket.remote)?;

        Ok(icmp_socket)
    }

    /* unused for now
    pub fn get_remote(&self) -> SockAddr
    {
        // gets the address that was specified for bind //
        return self.remote.to_owned();
    }*/

    pub fn send(&self, buf: &[u8]) -> Result<usize, std::io::Error>
    {
        // sends to the address specified in bind //
        self.inner.send_to( buf, &self.remote )
    }

    /* unused for now
    pub fn send_to(&self, buf: &[u8], host: &SockAddr) -> Result<usize, std::io::Error>
    {
        // sends to an arbitrary address //
        self.inner.send_to( buf, host )
    }*/

    pub async fn recv_from(&self, buf: &mut Vec<u8>) -> Result<(usize, SockAddr), std::io::Error>
    {
        // waits for data and then receives it into the specified buffer //
        let mut guard = self.readable().await?;

        // recv and then clear guard regardless of err state on socket //
        let recv_result = self.inner.recv_from(buf.spare_capacity_mut());
        guard.clear_ready();
        match recv_result
        {
            Ok((len, remote_sock)) =>
            {
                // TODO: SAFETY comment here
                unsafe
                {
                    buf.set_len(len);
                }
                Ok((len, remote_sock))
            }
            // forward to caller //
            Err(e) =>
            {
                // TODO: SAFETY comment here
                // make sure the buffer is burned //
                unsafe
                {
                    buf.set_len(0);
                }
                Err(e)
            }
        }
    }

    pub async fn readable(&self) -> Result<AsyncFdReadyGuard<'_, RawFd>, std::io::Error>
    {
        // blocks until socket is readable //
        Ok(self.async_fd.readable().await?)
    }
}
