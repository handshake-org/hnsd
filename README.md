# hnsd

SPV resolver daemon for the [Handshake][hns] network. Written in C for
speed/size/embedability.

## Architecture

hnsd exists as a 4-layer architecture:

1. A Handshake SPV node which syncs headers and requests name proofs and data
   from peers over the HNS P2P network.
2. An authoritative root server which translates the handshake name data to DNS
   responses. These responses appear as if they came from a root zone.
3. A recursive name server pointed at the authoritative server, which serves
   `.` as a stub zone
4. A hardcoded fallback for ICANN's root zone, residing in the authoritative
   layer.

A standard stub resolver can hit the recursive server with a request. The flow
looks something like this.

```
stub resolver
  -> +rd request
  -> recursive server
  -> libunbound
  -> +nord request
  -> authoritative server
  -> spv node
  -> proof request
  -> peer
```

Coming back, a response will look like:

```
peer
  -> proof response
  -> spv node
  -> authoritative server
  -> translated dns response
  -> libunbound
  -> recursive server
  -> dns response
  -> stub resolver
```

---

This daemon currently stores no data, and uses about 12mb of memory when
operating with a full DNS cache.

This architecture works well, given that there's two layers of caching between
the final resolution and the p2p layer (which entails the production of
slightly expensive-to-compute proofs). 

The recursive resolver leverages libunbound's built-in cache: there is, however, 
also a cache for the authoritative server. This is atypical when compared to a 
standard RFC 1035 nameserver which simply holds a zonefile in memory and serves it. 
All current ICANN-based root zone servers are RFC 1035 nameservers. We differ in
that our root zonefile is a blockchain. With caching for the root server, new proofs
only need to be requested every 6 hours (the duration of name tree update interval 
at the consensus layer). This substantially reduces load for full nodes who are
willing to serve proofs as a public service.

## Dependencies

### Build

- [libuv] >= 1.19.2 (included)

### Build/Runtime

- [libunbound] >= 1.6.0

hnsd will recursively build and statically link to `uv`, which is included in
the source repo.

## Installation

### Installing Dependencies

#### OSX

``` sh
$ brew install git automake autoconf libtool unbound
```

#### Linux

You're a Linux user so you probably already know what to do. Make sure you have
git, autotools, libtool, and unbound installed via whatever package manager
your OS uses.

### Cloning

``` sh
$ git clone git://github.com/handshake-org/hnsd.git
$ cd hnsd
```

### Building

``` sh
$ ./autogen.sh && ./configure && make
```

### Setup

Currently, hnsd will setup a recursive name server listening locally. If
you want to resolve names through the handshake network, this requires you to
change your resolv.conf to 127.0.0.1, as well as configure the daemon to listen
on port 53 -- this requires root access on OSX, and some hackery on Linux.

#### OSX

1. Open "System Preferences" on the panel/dock.
2. Select "Network".
3. Select "Advanced".
4. Select "DNS".
5. Here, you can add and remove nameservers. Remove all
   nameservers and add a single server: "127.0.0.1".
   You can change this back to google's servers
   (8.8.8.8 and 8.8.4.4) later if you want.
6. Run hnsd with `$ sudo ./hnsd --pool-size=4 --rs-host=127.0.0.1:53`.

#### Linux

First we need to alter our resolv.conf:

``` sh
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf > /dev/null
```

If you're using resolvconf, `/etc/resolvconf.conf` must be altered by setting:

``` conf
name_servers="127.0.0.1"
```

Secondly, we need to allow our daemon to listen on low ports, without root
access (much safer than running as root directly).

``` sh
$ sudo setcap 'cap_net_bind_service=+ep' /path/to/hnsd
```

Now run with:

``` sh
$ ./hnsd --pool-size=4 --rs-host=127.0.0.1:53
```

## Usage

``` sh
$ hnsd [options]
```

### Options

```
-c, --config <config>
  Path to config file.

-n, --ns-host <ip[:port]>
  IP address and port for root nameserver, e.g. 127.0.0.1:5369.

-r, --rs-host <ip[:port]>
  IP address and port for recursive nameserver, e.g. 127.0.0.1:53.

-i, --ns-ip <ip>
  Public IP for NS records in the root zone.

-u, --rs-config <config>
  Path to unbound config file.

-p, --pool-size <size>
  Size of peer pool.

-k, --identity-key <hex-string>
  Identity key for signing DNS responses as well as P2P messages.

-s, --seeds <seed1,seed2,...>
  Extra seeds to connect to on P2P network.
  Example:
    -s aorsxa4ylaacshipyjkfbvzfkh3jhh4yowtoqdt64nzemqtiw2whk@127.0.0.1

-l, --log-file <filename>
  Redirect output to a log file.

-d, --daemonize
  Fork and background the process.

-h, --help
  Help message.
```

## License

- Copyright (c) 2018, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[hns]: https://handshake.org
[libuv]: https://github.com/libuv/libuv
[libunbound]: https://github.com/NLnetLabs/unbound
