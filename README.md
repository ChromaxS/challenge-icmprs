# About
This program will ping the specified host, with some optional controls on behavior such as the
interval and count (max pings) to send. A quiet mode is also implemented for external programs
that just want to get a "thumbs up/down" (non-zero exit code if the host fails to respond at
least once).

## License
icmprs - An asynchronous ICMP ping implementation in Rust.
author: Christopher Eades 2023-10-07
license: CC0 1.0 Universal https://creativecommons.org/publicdomain/zero/1.0/

## Crates
### anyhow
The program is using anyhow to allow for some easy error handling feedback to the user but also
support any future implementation of custom errors.

### bincode/serde
Packet creation should be managable going into the future... better stated: as little bit-banging
as possible should be done directly on buffer arrays. bincode has great integration with serde
which means we get Rust structs serialized/deserialized which makes the clode cleaner and maintains
variable sized data packed into the right sizes without too much computation (ie a u16 being 2 bytes
on the wire but 8, on an Intel 64bit host, bytes). A good tradeoff of maintainability vs low level
control. We can also still bit bang if desired.

### clap
Easy implementation of behaviors for the program. Interval, count of packets, etc, are all easily
implemented clear as to what the program supports both in code and "for free" help messages that
allow the end user/automation to easily work with the program. A lot of boilerplate is eliminated
as well, ie sanity checking of arguments.

### socket2
There are some crates that provide an ICMP interface but since ping is so simple to implement in
both IPv4 and IPv6, the socket2 crate is a good trade off. Control over packet creation/options
and some of the requirements (ie really low intervals and async sending/reporting of pings) is
much more important than "just send a ping." We can easily integrate with a tokio::select! loop
which allows us to both send and report responses (or lack thereof).

### tokio
Async send/recv is required and tokio gives us a really good event loop built around select!
which will handle low level responses to timers (reporting of response/lack of), sending packets,
and handling creature comforts like signal handlers.

# Usage
At its most basic use, compile the program with `cargo build` and then run with `cargo run -- --help` to get the options that can be used:
```
icmprs (master) $ cargo run -- --help
    Finished dev [unoptimized + debuginfo] target(s) in 0.07s
     Running `target/debug/icmprs --help`
A rust ICMP echo request (ping) utility.

Usage: icmprs [OPTIONS] <HOST_OR_ARGS>

Arguments:
  <HOST_OR_ARGS>  Host (or address).

Options:
  -o, --output <OUTPUT>      Output mode; defaults to Regular. --quiet disables output entirely. [default: default] [possible values: default, regular, quiet]
  -c, --count <COUNT>        Amount of requests to send. [default: 4]
  -i, --interval <INTERVAL>  Interval, in milliseconds, between requests. [default: 1000]
  -t, --timeout <TIMEOUT>    Timeout, in milliseconds, to wait for requests. [default: 5000]
  -s, --size <SIZE>          Size of the ICMP echo data to send. [default: 32]
  -q, --quiet                Program won't output any regular output (equivalent to -o=quiet).
  -h, --help                 Print help
  -V, --version              Print version

```

The simplest usage is to run with just a host:
```
icmprs (master) $ sudo cargo run -- 192.168.2.2
    Finished dev [unoptimized + debuginfo] target(s) in 0.07s
     Running `target/debug/icmprs --help`
Pinging 192.168.2.2 (192.168.2.2) with 32 byte(s) of data...

32 bytes from 192.168.2.2: icmp_seq=1 ttl=62: 11.038 ms
32 bytes from 192.168.2.2: icmp_seq=2 ttl=62: 0.692 ms
32 bytes from 192.168.2.2: icmp_seq=3 ttl=62: 0.688 ms

Sent 3 echo requests and received 3 successful replies.
```

Note: `cargo run` may not run under `sudo` if it's installed local to the user's home directory. Using `sudo -E $(which cargo) run -- 192.168.2.2` or running the binary directly from the target directory may be necessary.

When running in regular output mode, some ICMP errors are handled, ie host unreachable and TTL exceeded:
```
icmprs (master) $ sudo target/debug/icmprs --output=regular 192.168.2.3,3,200
Pinging 192.168.2.3 (192.168.2.3) with 32 byte(s) of data...

Reply from 192.168.2.1: icmp_seq=1 ttl=63: host unreachable
Reply from 192.168.1.101: icmp_seq=1: 5200.106 ms -- timed out waiting for response
Reply from 192.168.1.101: icmp_seq=2: 5000.593 ms -- timed out waiting for response
Reply from 192.168.1.101: icmp_seq=3: 5199.466 ms -- timed out waiting for response

Sent 3 echo requests and received 0 successful replies.
```

## Docker

A `rust.dockerfile` is provided so that a container can be built and used to run the program:
```
icmprs (master) $ docker build --tag challenge/icmprs -f rust.dockerfile .
Step 1/11 : FROM rust AS base
 ---> 2ef5e9cadcb8
....
Step 8/11 : RUN cargo build --release
 ---> Running in d828b41e4cb1
    Updating crates.io index
 Downloading crates ...
....
   Compiling icmprs v0.1.0 (/opt)
    Finished release [optimized] target(s) in 37.44s
Successfully built 942809d31e2f
Successfully tagged challenge/icmprs:latest
```

The program can be run right from the container:
```
icmprs (master) $ docker run --rm challenge/icmprs www.google.com
Pinging www.google.com (142.250.191.100) with 32 byte(s) of data...

32 bytes from 142.250.191.100: icmp_seq=1 ttl=59: 7.189 ms
32 bytes from 142.250.191.100: icmp_seq=2 ttl=59: 7.144 ms
32 bytes from 142.250.191.100: icmp_seq=3 ttl=59: 7.280 ms
32 bytes from 142.250.191.100: icmp_seq=4 ttl=59: 6.879 ms

Sent 4 echo requests and received 4 successful replies.
```

Note: RAW socket capabilities may be necessary depending on the docker daemon's host setup, if so, add these options to the above `docker run` command: `--cap-add NET_RAW --sysctl net.ipv4.ping_group_range="0 0"`