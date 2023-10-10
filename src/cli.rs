/*

icmprs - An asynchronous ICMP ping implementation in Rust.
author: Christopher Eades 2023-10-07
license: CC0 1.0 Universal https://creativecommons.org/publicdomain/zero/1.0/

*/


use anyhow;
use clap::{Parser, ValueEnum};


#[derive(Clone, Parser, ValueEnum, Debug)]
pub(crate) enum OutputMode
{
    CSV,
    Default,
    Regular,
}


#[derive(Parser, Debug)]
#[command(author = "Christopher Eades", version = "1.0", about = "A rust ICMP echo request (ping) utility.", long_about = None)]
pub(crate) struct Args
{
    #[arg(required = true, help = "Host (or address) or CSV format: host,count,interval (implies --output=csv)")]
    pub host_or_args: String,

    #[arg(value_enum, short, long, default_value_t = OutputMode::Default, help = "Output mode; defaults to Regular. --quiet disables output entirely.")]
    pub output: OutputMode,

    // amount of requests to send //
    #[arg(short, long, default_value_t = 4, value_parser = count_range, help = "Amount of requests to send.")]
    pub count: u64,

    // interval between requests //
    // REQUIREMENT: The target IP will have a configurable ping interval in milliseconds. Minimum: 1 Maximum: 1000.
    // Requests should be sent at this interval, regardless of when the reply is received.
    #[arg(short, long, default_value_t = 1000, value_parser = interval_range, help = "Interval, in milliseconds, between requests.")]
    pub interval: u64,

    // echo request timeout //
    // REQUIREMENT: ICMP Echo timeout should be set to 5 seconds.
    #[arg(short, long, default_value_t = 5000, value_parser = timeout_range, help = "Timeout, in milliseconds, to wait for requests.")]
    pub timeout: u64,

    // size of the packet //
    #[arg(short, long, default_value_t = 32, help = "Size of the ICMP echo data to send.")]
    pub size: usize,
    
    // quiet or not //
    #[arg(short, long, default_value_t = false, help = "Program won't output any regular output.")]
    pub quiet: bool,
}

// some support for the cli parser //


pub fn count_range(count_parsed: &str) -> Result<u64, anyhow::Error>
{
    // require the count to be from 1 to 10 //
    match count_parsed.parse()
    {
        Ok(count) if count == 0 => Err(anyhow::anyhow!( "The count must be at least 1: {}", count )),
        Ok(count) if count > 0 && count <= 10 => Ok(count),
        _ => Err(anyhow::anyhow!( "The count must be a value between 1 and 10: {}", count_parsed )),
    }
}

pub fn interval_range(interval_parsed: &str) -> Result<u64, anyhow::Error>
{
    // require the interval to be from 1 to 1000ms... basically no flooding and no super long requests //
    match interval_parsed.parse()
    {
        Ok(interval) if interval == 0 => Err(anyhow::anyhow!( "The interval must be at least 1ms: {}", interval )),
        Ok(interval) if interval > 0 && interval <= 1000 => Ok(interval),
        _ => Err(anyhow::anyhow!( "The interval must be a value between 1 and 1000ms: {}", interval_parsed )),
    }
}

pub fn timeout_range(timeout_parsed: &str) -> Result<u64, anyhow::Error>
{
    // require the timeout to be from 1 to 10000ms //
    match timeout_parsed.parse()
    {
        Ok(timeout) if timeout == 0 => Err(anyhow::anyhow!( "The timeout must be at least 1ms: {}", timeout )),
        Ok(timeout) if timeout > 0 && timeout <= 10000 => Ok(timeout),
        _ => Err(anyhow::anyhow!( "The timeout must be a value between 1 and 10000ms: {}", timeout_parsed )),
    }
}