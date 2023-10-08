/*

icmprs - An asynchronouse ICMP ping implementation in Rust.
author: Christopher Eades 2023-10-07
license: CC0 1.0 Universal https://creativecommons.org/publicdomain/zero/1.0/

This program will ping the specified host, with some optional controls on behavior such as the
interval and count (max pings) to send. A quiet mode is also implemented for external programs
that just want to get a "thumbs up/down" (non-zero exit code if the host fails to respond at
least once).

anyhow
The program is using anyhow to allow for some easy error handling feedback to the user but also
support any future implementation of custom errors.

bincode/serde
Packet creation should be managable going into the future... better stated: as little bit-banging
as possible should be done directly on buffer arrays. bincode has great integration with serde
which means we get Rust structs serialized/deserialized which makes the clode cleaner and maintains
variable sized data packed into the right sizes without too much computation (ie a u16 being 2 bytes
on the wire but 8, on an Intel 64bit host, bytes). A good tradeoff of maintainability vs low level
control. We can also still bit bang if desired.

clap
Easy implementation of behaviors for the program. Interval, count of packets, etc, are all easily
implemented clear as to what the program supports both in code and "for free" help messages that
allow the end user/automation to easily work with the program. A lot of boilerplate is eliminated
as well, ie sanity checking of arguments.

socket2
There are some crates that provide an ICMP interface but since ping is so simple to implement in
both IPv4 and IPv6, the socket2 crate is a good trade off. Control over packet creation/options
and some of the requirements (ie really low intervals and async sending/reporting of pings) is
much more important than "just send a ping." We can easily integrate with a tokio::select! loop
which allows us to both send and report responses (or lack thereof).

tokio
Async send/recv is required and tokio gives us a really good event loop built around select!
which will handle low level responses to timers (reporting of response/lack of), sending packets,
and handling creature comforts like signal handlers.

*/


use anyhow;
use clap::Parser;
use env_logger;
use log;
use rand::{self, Rng};
use socket2::{SockAddr, Socket, Domain, Type, Protocol};
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::os::fd::AsFd;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::sync::Notify;
use tokio::time::Interval;

mod cli;
use cli::Args;
mod ipv4;
use ipv4::icmp;


#[tokio::main]
async fn main()
{
    // A rust ICMP echo request (ping) utility //

    // handle clap args first //
    let mut args = Args::parse();

    // only set RUST_LOG environment variable if it's not already set //
    if env::var("RUST_LOG").is_err() && !args.quiet
    {
        env::set_var( "RUST_LOG", "INFO" );
    }
    env_logger::init();

    // handle input arguments //
    match args.host_or_args.to_owned().split(",").collect::<Vec<&str>>()
    {
        args_csv if args_csv.len() == 3 =>
        {
            // force CSV output //
            if matches!( args.output, cli::OutputMode::Default )
            {
                args.output = cli::OutputMode::CSV;
            }

            // parse host: arg 1 //
            args.host_or_args = args_csv[0].to_owned();

            // parse count: arg 2 //
            args.count = match cli::count_range(args_csv[1])
            {
                Ok(count) => count,
                Err(e) => panic!( "CSV argument 2, count, invalid: {}", e ),
            };

            // parse interval: arg 3 //
            args.interval = match cli::interval_range(args_csv[2])
            {
                Ok(interval) => interval,
                Err(e) => panic!( "CSV argument 3, interval, invalid: {}", e ),
            };
        },
        args_csv if args_csv.len() == 1 =>
        {
            // regular is the default output mode //
            if matches!( args.output, cli::OutputMode::Default )
            {
                args.output = cli::OutputMode::Regular;
            }
        },
        _ => panic!("CSV arguments to program should be: host,count,interval"),
    }

    // first resolve host in-case there's any issues with it //
    let host_addr = resolve_host_addr(&args.host_or_args).unwrap();

    // create the icmp socket and setup tokio stuff //
    let socket = setup_socket(&host_addr).unwrap();
    let shutdown_notify = Notify::new();
    let mut echo_interval = tokio::time::interval(Duration::from_millis(args.interval));

    if matches!( args.output, cli::OutputMode::Regular ) && !args.quiet
    {
        log::info!( "pinging {} ({}) with {} byte(s) of data...", &args.host_or_args, &host_addr.ip(), 32 );
    }
    log::debug!( "count (amount of requests to send) is: {}", args.count );
    log::debug!( "interval is {} millisecond(s)", args.interval );

    main_loop( args.quiet, &shutdown_notify, &mut echo_interval, args.count, &host_addr, &socket, args.size ).await.unwrap();
}

fn resolve_host_addr(host: &String) -> anyhow::Result<SocketAddr>
{
    // resolve host String to SocketAddr structure //

    // to_socket_addrs wants a :port so this is appended but the user may specify this so we'll need to deal with that... //
    // the idea is IPv6 addresses may be passed so rather than become a poor validator here, we just are concerned with :port //
    // we'll simply assume any amount of colons means it's an IPv6 address and encapsulate the host with []'s and then let
    // further validation happen from to_socket_addrs (this is despite knowing things like aaaa:: is a valid IPv6 address,
    // again, we don't want to be in the business of validating this) //
    let host_final = match host.to_owned().split(",").collect::<Vec<&str>>()
    {
        components if components.len() > 1 => format!( "[{}]", &host ),
        _ => host.to_owned(),
    };

    // do the resolve //
    let host_addr = match format!( "{}:0", &host_final ).to_socket_addrs()
    {
        Ok(mut addr) => match addr.next()
        {
            Some(addr) => addr,
            None => panic!( "specified host, {}, could not be resolved!", host_final ),
        },
        Err(e) => return Err(anyhow::anyhow!( "invalid host, {}, specified: {}", host_final, e )),
    };
    Ok(host_addr)
}

fn setup_socket(host_addr: &SocketAddr) -> anyhow::Result<Socket>
{
    let socket = if host_addr.is_ipv4()
    {
        Socket::new_raw( Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4) ).map_err(anyhow::Error::from)
    }else if host_addr.is_ipv6()
    {
        // TODO: v6... //
        return Err(anyhow::anyhow!("does not support IPv6!"));
    }else
    {
        return Err(anyhow::anyhow!( "specified host, {}, is neither IPv4 or IPv6!", host_addr ));
    }?;

    // allow us to do non-blocking I/O //
    socket.set_nonblocking(true)?;

    Ok(socket)
}

async fn main_loop(
    quiet: bool,
    shutdown_notify: &Notify,
    echo_interval: &mut Interval,
    count: u64,
    host_addr: &SocketAddr,
    socket: &Socket,
    data_size: usize) -> anyhow::Result<()>
  {
    // ctrl+c and interrupt handler //
    let mut signal_interrupt_stream = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
    let mut signal_terminate_stream = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    // shutdown notification //
    let shutdown_notification = shutdown_notify.notified();

    // make a random identifier //
    let mut rng = rand::thread_rng();
    let identifier: u16 = rng.gen();
    // start the sequence at 1 //
    let mut sequence: u16 = 1;
    // keep track of packets sent //
    let mut requests_sent = 0;

    // we'll use this for sending and recv'ing in tokio::select! //
    let async_fd = AsyncFd::new(socket.as_fd())?;

    log::debug!("starting main_loop...");
    tokio::pin!(shutdown_notification);
    loop
    {
        tokio::select!
        {
            // shutdown //
            _ = signal::ctrl_c() =>
            {
                log::warn!("caught CTRL+C -- shutting down");
                shutdown_notify.notify_waiters();
                break;
            },
            _ = signal_interrupt_stream.recv() =>
            {
                log::warn!("received SIGINT -- shutting down");
                shutdown_notify.notify_waiters();
                break;
            },
            _ = signal_terminate_stream.recv() =>
            {
                log::warn!("received SIGTERM -- shutting down");
                shutdown_notify.notify_waiters();
                break;
            },
            _ = &mut shutdown_notification =>
            {
                log::warn!("shutdown triggered from notification!");
                break;
            },
            // echo requests //
            _ = echo_interval.tick() =>
            {
                if requests_sent >= count
                {
                    continue;
                }
                log::debug!("echo request tick!");
                sequence = sequence + 1;
                requests_sent = requests_sent + 1;
            }
            readable = async_fd.readable() =>
            {
                match readable
                {
                    Ok(guard) =>
                    {
                        let mut buf = Vec::with_capacity(icmp::ICMPV4_PKT_BUF_SIZE + data_size);
                        let ( len, remote_sock ) = match socket.recv_from(buf.spare_capacity_mut())
                        {
                            Ok((len, remote_sock)) => (len, remote_sock),
                            Err(e) =>
                            {
                                unsafe
                                {
                                    buf.set_len(0);
                                }
                                log::error!( "error receiving ICMP packet: {}", e );
                                shutdown_notify.notify_waiters();
                                continue;
                                //return 0;
                            }
                        };
                        unsafe
                        {
                            buf.set_len(len);
                        }
                        if host_addr.is_ipv4()
                        {
                            match ipv4::icmp::ipv4_handle_icmp_packet( &remote_sock, &buf, identifier, sequence )
                            {
                                Err(e) =>
                                {
                                    log::error!( "IPv4 ICMP handler error: {}", e );
                                    continue;
                                },
                                _ => continue,
                            }
                        }
                    },
                    Err(e) => log::error!( "unable to check readystate for ICMP socket: {}", e ),
                }
            }
        }
    }

    log::debug!("stopped main_loop");

    Ok(())
}
