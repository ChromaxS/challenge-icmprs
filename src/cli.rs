use anyhow;
use clap::Parser;


#[derive(Parser, Debug)]
#[command(author = "Christopher Eades", version = "1.0", about = "A rust ICMP echo request (ping) utility.", long_about = None)]
pub(crate) struct Args
{
    #[arg(last = true, required = true, help = "Host (or address) or CSV format: host,count,interval (implies --output-csv)")]
    pub host_or_args: String,

    #[arg(short, long, default_value_t = false, help = "Output CSV format instead of interactive output. --quiet disables output entirely.")]
    pub output_csv: bool,

    // amount of requests to send //
    #[arg(short, long, default_value_t = 4, value_parser = count_range, help = "Amount of requests to send.")]
    pub count: u64,

    // interval between requests //
    // REQUIREMENT: The target IP will have a configurable ping interval in milliseconds. Minimum: 1 Maximum: 1000.
    // Requests should be sent at this interval, regardless of when the reply is received.
    #[arg(short, long, default_value_t = 1000, value_parser = interval_range, help = "Interval, in milliseconds, between requests.")]
    pub interval: u64,

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
        Ok(count) if count == 0 => Err(anyhow::anyhow!("The count must be at least 1.")),
        Ok(count) if count > 0 && count <= 10 => Ok(count),
        _ => Err(anyhow::anyhow!("The count must be a value between 1 and 10.")),
    }
}

pub fn interval_range(interval_parsed: &str) -> Result<u64, anyhow::Error>
{
    // require the interval to be from 1 to 1000ms... basically no flooding and no super long requests //
    match interval_parsed.parse()
    {
        Ok(interval) if interval == 0 => Err(anyhow::anyhow!("The interval must be at least 1ms.")),
        Ok(interval) if interval > 0 && interval <= 1000 => Ok(interval),
        _ => Err(anyhow::anyhow!("The interval must be a value between 1 and 1000ms.")),
    }
}