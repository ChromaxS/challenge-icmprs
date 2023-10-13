/*

icmprs - An asynchronous ICMP ping implementation in Rust.
author: Christopher Eades 2023-10-07
license: CC0 1.0 Universal https://creativecommons.org/publicdomain/zero/1.0/

*/

use anyhow;
use clap::Parser;
use env_logger;
use hostname;
use log;
use rand::{self, Rng};
use socket2::SockAddr;
use std::env;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process::exit;
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::Notify;

mod cli;
use cli::Args;
mod ip;
mod ipv4;

const IPV4_MAX_PACKET_SIZE: usize = 4096;

#[derive(Clone)]
pub(crate) struct IcmpEchoRequest {
    pub instant: Instant,
    pub sequence: u16,
}

pub(crate) struct IcmpProgramState {
    pub started: Instant,
    pub responded_successfully: u64,
    pub output: cli::OutputMode,

    pub host_addr: SocketAddr,
    pub identifier: u16,
    pub sequence: u16,

    pub sent_total: u64,
    pub sent: Vec<IcmpEchoRequest>,
}

#[tokio::main]
async fn main() {
    // A rust ICMP echo request (ping) utility //

    // handle clap args first //
    let mut args = Args::parse();
    if args.quiet {
        args.output = crate::cli::OutputMode::Quiet;
    }
    if matches!( args.output, crate::cli::OutputMode::Default ) {
        args.output = crate::cli::OutputMode::Regular;
    }

    // only set RUST_LOG environment variable if it's not already set //
    if env::var("RUST_LOG").is_err() && !matches!( args.output, crate::cli::OutputMode::Quiet ) {
        env::set_var("RUST_LOG", "INFO");
    }
    env_logger::init();

    // first resolve host in-case there's any issues with it //
    let host_addr = resolve_host_addr(&args.host_or_args).unwrap();

    // create socket //
    let sockaddr = SockAddr::from(host_addr.to_owned());
    let socket = ip::IcmpSocket::bind(&sockaddr).unwrap();

    // create shutdown event //
    let shutdown_notify = Notify::new();

    if matches!(args.output, cli::OutputMode::Regular) {
        println!(
            "Pinging {} ({}) with {} byte(s) of data...",
            &args.host_or_args,
            &host_addr.ip(),
            32
        );
        println!("");
    }
    log::debug!("count (amount of requests to send) is: {}", args.count);
    log::debug!("interval is {} millisecond(s)", args.interval);

    if true
        == main_loop(&socket, &args, &shutdown_notify, &host_addr)
            .await
            .unwrap()
    {
        exit(0);
    }
    exit(1);
}

fn resolve_host_addr(host: &String) -> anyhow::Result<SocketAddr> {
    // resolve host String to SocketAddr structure //

    // to_socket_addrs wants a :port so this is appended but the user may specify this so we'll need to deal with that... //
    // the idea is IPv6 addresses may be passed so rather than become a poor validator here, we just are concerned with :port //
    // we'll simply assume any amount of colons means it's an IPv6 address and encapsulate the host with []'s and then let
    // further validation happen from to_socket_addrs (this is despite knowing things like aaaa:: is a valid IPv6 address,
    // again, we don't want to be in the business of validating this) //
    let host_final = match host.to_owned().split(',').collect::<Vec<&str>>() {
        components if components.len() > 1 => format!("[{}]", &host),
        _ => host.to_owned(),
    };

    // do the resolve //
    let host_addr = match format!("{}:0", &host_final).to_socket_addrs() {
        Ok(mut addr) => match addr.next() {
            Some(addr) => addr,
            None => panic!("specified host, {}, could not be resolved!", host_final),
        },
        Err(e) => {
            return Err(anyhow::anyhow!(
                "invalid host, {}, specified: {}",
                host_final,
                e
            ))
        }
    };
    Ok(host_addr)
}

async fn main_loop(
    socket: &ip::IcmpSocket,
    args: &cli::Args,
    shutdown_notify: &Notify,
    host_addr: &SocketAddr,
) -> anyhow::Result<bool> {
    // ctrl+c and interrupt handler //
    let mut signal_interrupt_stream = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
    let mut signal_terminate_stream = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    // shutdown notification //
    let shutdown_notification = shutdown_notify.notified();

    // program state to pass into everything //
    let mut rng = rand::thread_rng();
    let mut program_state = IcmpProgramState {
        started: Instant::now(),
        responded_successfully: 0,
        output: args.output.clone(),
        host_addr: host_addr.to_owned(),

        // make a random identifier //
        identifier: rng.gen(),
        // start the sequence at 1 //
        sequence: 1,
        // keep track of packets sent //
        sent_total: 0,

        sent: vec![],
    };
    log::debug!(
        "identifier is {} and starting sequence: {}",
        program_state.identifier,
        program_state.sequence
    );

    // get our IP so we can report timeouts //
    let host_name = hostname::get()?;
    let host_ip = resolve_host_addr(&host_name.to_string_lossy().to_string())?;

    // allocate the receiving buffer //
    let mut buf_recv = Vec::with_capacity(IPV4_MAX_PACKET_SIZE);

    // finally setup our echo interval tick //
    let mut echo_interval = tokio::time::interval(Duration::from_millis(args.interval));

    log::debug!("starting main_loop...");
    tokio::pin!(shutdown_notification);
    loop {
        buf_recv.clear();
        tokio::select! {
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
                log::debug!("shutdown triggered from notification!");
                break;
            },
            // echo requests //
            _ = echo_interval.tick() => { icmp_send_tick( args, shutdown_notify, &host_ip, socket, &mut program_state )?; },
            // icmp incoming (echo replies) //
            received = socket.recv_from(&mut buf_recv) =>
            {
                match received
                {
                    Ok(received) =>
                    {
                        if program_state.host_addr.is_ipv4()
                        {
                            match ipv4::ipv4_handle_packet( &received.1, &buf_recv, &mut program_state )
                            {
                                Err(e) =>
                                {
                                    log::error!( "IPv4 handler error: {}", e );
                                    continue;
                                },
                                _ =>
                                {
                                    if args.count > 0 && program_state.sent_total >= args.count && program_state.sent.is_empty()
                                    {
                                        // we're done //
                                        log::debug!( "echo request count, {}, reached after echo reply and no outstanding replies -- done", args.count );
                                        shutdown_notify.notify_waiters();
                                    }
                                    continue;
                                }
                            }
                        }
                    },
                    Err(e) => log::error!( "unable to recv_from on ICMP socket: {}", e ),
                }
            }
        }
    }

    log::debug!(
        "stopped main_loop -- ran for {} second(s)",
        (Instant::now() - program_state.started).as_secs_f64()
    );

    if matches!(program_state.output, cli::OutputMode::Regular)
    {
        println!("");
        println!(
            "Sent {} echo requests and received {} successful replies.",
            program_state.sent_total, program_state.responded_successfully
        );
    }

    Ok(program_state.responded_successfully == program_state.sent_total)
}

fn icmp_send_tick(
    args: &cli::Args,
    shutdown_notify: &Notify,
    host_ip: &SocketAddr,
    socket: &ip::IcmpSocket,
    program_state: &mut IcmpProgramState,
) -> anyhow::Result<bool> {
    // maybe send an ICMP packet -- returns bool whether on was sent or not //

    // clear out timed out requests //
    // this isn't too efficient (at larger amounts of pings, like hundreds of thousands) but it gives us feedback at the right time //
    // ie 5 seconds after each 200ms interval //
    let now = Instant::now();
    let timeout = Duration::from_millis(args.timeout);
    let mut timed_out_requests = Vec::<IcmpEchoRequest>::new();
    program_state.sent.retain_mut(|sent| {
        // if the timeout duration hasn't been hit then skip this //
        if now - sent.instant < timeout {
            return true;
        }

        timed_out_requests.push(sent.clone());

        false
    });
    for timed_out_request in timed_out_requests.iter() {
        program_state.output_error(
            &host_ip.ip(),
            Some(timed_out_request.instant),
            timed_out_request.sequence,
            0,
            "timed out waiting for response".to_string(),
        );
    }

    // make sure we don't send more echo requests than requested //
    if args.count > 0 && program_state.sent_total >= args.count {
        if !program_state.has_sequences() {
            // we're done //
            log::debug!( "echo request count, {}, reached on echo request tick and no outstanding replies -- done", args.count );
            shutdown_notify.notify_waiters();
        }
        return Ok(false);
    }
    log::debug!("echo request {} tick!", program_state.sent_total);

    if program_state.host_addr.is_ipv4() {
        // send //
        let buffer = ipv4::icmp::ipv4_icmp_create_echo_request(
            program_state.identifier,
            program_state.sequence,
            args.size,
        )?;
        socket.send(&buffer)?;

        // track //
        program_state.sent.push(IcmpEchoRequest {
            instant: Instant::now(),
            sequence: program_state.sequence,
        });

        // and increment the sequence for next go //
        program_state.sequence = program_state.sequence.wrapping_add(1);
    }

    program_state.sent_total += 1;

    Ok(true)
}

impl IcmpProgramState {
    pub fn has_sequences(&self) -> bool {
        // returns whether there's any sequences being tracked //
        !self.sent.is_empty()
    }

    pub fn remove_sequence(&mut self, sequence: u16) -> Option<Instant> {
        // removes the specified sequence and returns the original Instant it was sent if found //

        // this isn't the most efficient but we're not working with a large list of packets and even then so, it'd have to be hundreds of thousands or so //
        // to be really bad //
        let mut found_sequence = None;
        self.sent.retain_mut(|sent| {
            // see if this is the packet we're looking for //
            if sent.sequence != sequence {
                return true;
            }

            log::debug!("dequeued sent tracking sequence ID: {}", sent.sequence);
            found_sequence = Some(sent.instant);

            false
        });
        found_sequence
    }

    pub fn output_error(
        &self,
        remote_ip: &IpAddr,
        instant_echo_request: Option<Instant>,
        sequence: u16,
        ttl: u8,
        error: String,
    ) {
        // outputs an error (if not set to quiet) //
        match self.output {
            crate::cli::OutputMode::Default | crate::cli::OutputMode::Regular => {
                // regular output //
                match instant_echo_request {
                    Some(instant_echo_request) => {
                        let request_millis =
                            (Instant::now() - instant_echo_request).as_secs_f64() * 1000.0;
                        println!(
                            "Reply from {}: icmp_seq={} ttl={}: {:.3} ms -- {}",
                            remote_ip, sequence, ttl, request_millis, error
                        );
                    }
                    _ => println!(
                        "Reply from {}: icmp_seq={} ttl={}: {}",
                        remote_ip, sequence, ttl, error
                    ),
                }
            },
            crate::cli::OutputMode::Quiet => {},
        }
    }

    pub fn output_ping(
        &self,
        data_bytes: usize,
        remote_ip: &IpAddr,
        instant_echo_request: Instant,
        sequence: u16,
        ttl: u8,
    ) {
        match self.output {
            crate::cli::OutputMode::Default | crate::cli::OutputMode::Regular => {
                // regular output //
                let request_millis = (Instant::now() - instant_echo_request).as_secs_f64() * 1000.0;
                println!(
                    "{} bytes from {}: icmp_seq={} ttl={}: {:.3} ms",
                    data_bytes, remote_ip, sequence, ttl, request_millis
                );
            },
            crate::cli::OutputMode::Quiet => {},
        }
    }
}
