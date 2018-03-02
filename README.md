# hskd

Small daemon to resolve domain names through handshake.

## Architecture

hskd exists as a 3-layer architecture:

1. A handshake SPV node wich syncs headers and requests name proofs and data
   from peers over the HSK P2P network.
2. An authoritative root server which translates the handshake name data to DNS
   responses. These responses appear as if they came from a root zone.
3. A recursive name server pointed at the authoritative server, which serves
   `.` as a stub zone

A standard stub resolver can hit the recursive server with a request. The flow
looks something like this.

```
stub resolver
  -> +rd request
  -> recursive server
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
  -> recursive server
  -> dns response
  -> stub resolver
```

## Setup

Currently, hskd will setup a recursive name server listening on port 53. If you
want to resolve names through the handshake network, this requires you to
change your resolv.conf to 127.0.0.1.

e.g.

``` sh
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolve.conf > /dev/null
```

If you're using resolvconf, `/etc/resolvconf.conf` must be altered by setting:

``` conf
name_servers="127.0.0.1"
```

## Build/Runtime Deps

- lssl >= 1.1.0
- lcrypto >= 1.1.0
- lgmp >= 6.1.2 (optional)

hskd will recursively build and statically link to `uv`, `ldns`, `secp256k1`,
and `unbound` which are included in the source repo.

## Building

``` sh
$ ./autogen.sh
$ ./configure
$ make
```

## Usage

``` sh
$ hskd [options]
```

### Options

```
-c, --config <config>
  Path to config file.

-n, --ns-host <ip[@port]>
  IP address and port for root nameserver, e.g. 127.0.0.1@5369.

-r, --rs-host <ip[@port>
  IP address and port for recursive nameserver, e.g. 127.0.0.1@53.

-i, --ns-ip <ip>
  Public IP for NS records in the root zone.

-u, --rs-config <config>
  Path to unbound config file.

-p, --pool-size <size>
  Size of peer pool.

-k, --identity-key <hex-string>
  Identity key for signing DNS responses.

-s, --seeds <seed1,seed2,...>
  Seeds to connect to on P2P network.

-h, --help
  Help message.
```
