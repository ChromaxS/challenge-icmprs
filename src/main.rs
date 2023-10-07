/*

icmprs - An asynchronouse ICMP ping implementation in Rust.
author: Christopher Eades 2023-10-07
license: CC0 1.0 Universal https://creativecommons.org/publicdomain/zero/1.0/

This program will ping the specified host, with some optional controls on behavior such as the
interval and count (max pings) to send. A quiet mode is also implemented for external programs
that just want to get a "thumbs up/down" (non-zero exit code if the host fails to respond at
least once).

*/


use anyhow;
use clap::Parser;
use env_logger;
use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use log;

mod cli;
use cli::Args;


fn main()
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
            args.output_csv = true;

            // parse host: arg 1 //
            args.host_or_args = args_csv[0].to_owned();

            // parse count: arg 2 //
            args.count = match cli::count_range(args_csv[1])
            {
                Ok(count) => count,
                Err(e) => panic!( "CSV argument 2, count, invalid: {}", e ),
            };

            // parse interval: arg 3 //
            args.count = match cli::count_range(args_csv[2])
            {
                Ok(count) => count,
                Err(e) => panic!( "CSV argument 2, count, invalid: {}", e ),
            };
        },
        args_csv if args_csv.len() == 1 => {},
        _ => panic!("CSV arguments to program should be: host,count,interval"),
    }

    // first resolve host in-case there's any issues with it //
    let host_addr = resolve_host_addr(&args.host_or_args).unwrap();

    if !args.output_csv
    {
        println!("ASDASDDSA");
        log::info!( "pinging {} ({}) with {} byte(s) of data...", &args.host_or_args, &host_addr.ip(), 32 );
    }
    log::debug!( "count (amount of requests to send) is {} millisecond(s)", args.count );
    log::debug!( "interval is {} millisecond(s)", args.interval );
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
