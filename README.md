# hnsd

SPV resolver daemon for the [Handshake][hns] network. Written in C for
speed/size/embedability.

## Architecture

hnsd exists as a 4-layer architecture:

1. An SPV node which syncs headers and requests name proofs and data from peers
   over the HNS P2P network.
2. An authoritative root server which translates the HNS name data to DNS
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

## Installing Dependencies

### OSX

``` sh
$ brew install git automake autoconf libtool unbound
```

### Linux

You're a Linux user so you probably already know what to do. Make sure you have
git, autotools, libtool, and unbound installed via whatever package manager
your OS uses.
You can install these dependencies on any Ubuntu/Debian style linux using
`sudo apt install -y autotools-dev libtool libunbound-dev`

### Windows

Windows builds are made natively with MSYS2 / MinGW.  This uses the MinGW
libunbound and OpenSSL packages provided by MSYS2.

1. Install MSYS2 from https://www.msys2.org - follow the instructions on that page
2. Install dependencies - do one of the following in an MSYS2 shell
   - x86_64: `pacman -S base-devel mingw-w64-x86_64-toolchain mingw-w64-x86_64-unbound mingw-w64-x86_64-crt-git`
   - x86: `pacman -S base-devel mingw-w64-i686-toolchain mingw-w64-i686-unbound mingw-w64-i686-crt-git`
3. (Optional) You can install git if you want to use it from the MSYS2 shell - `pacman -S git`
   - Git for Windows works fine too but avoid mixing the two, they may not handle line endings the same way
4. Then build normally from the MSYS2 shell.

The Windows build will dynamically link to the MinGW libunbound and OpenSSL DLLs.
You can run it from the MSYS2 shell, which sets PATH appropriately, copy those
DLLs to the hnsd directory, etc.

## Cloning

``` sh
$ git clone git://github.com/handshake-org/hnsd.git
$ cd hnsd
```

## Building

``` sh
$ ./autogen.sh && ./configure && make
```

### Optional

``` sh
$ sudo make install
```

## Setup

Currently, hnsd will setup a recursive name server listening locally. If
you want to resolve names through the handshake network, this requires you to
change your resolv.conf to 127.0.0.1, as well as configure the daemon to listen
on port 53 -- this requires root access on OSX, and some hackery on Linux.

### OSX

1. Open "System Preferences" on the panel/dock.
2. Select "Network".
3. Select "Advanced".
4. Select "DNS".
5. Here, you can add and remove nameservers. Remove all
   nameservers and add a single server: "127.0.0.1".
   You can change this back to google's servers
   (8.8.8.8 and 8.8.4.4) later if you want.
6. Run hnsd with `$ sudo ./hnsd -p 4 -r 127.0.0.1:53`.

### Linux

First we need to alter our resolv.conf:

``` sh
echo 'nameserver 127.0.0.1' | sudo tee /etc/resolv.conf > /dev/null
```

Secondly, we need to allow our daemon to listen on low ports, without root
access (much safer than running as root directly).

``` sh
$ sudo setcap 'cap_net_bind_service=+ep' /path/to/hnsd
```

Now run with:

``` sh
$ ./hnsd -p 4 -r 127.0.0.1:53
```

### Using a static resolv.conf

On Linux, there are a few services which may try to automatically overwrite
your `resolv.conf`. _resolvconf_, _dhcpcd_, and _NetworkManager_ are usually
the culprits here.

#### resolvconf

If you're using resolvconf, `/etc/resolvconf.conf` must be modified:

``` sh
$ sudo vi /etc/resolvconf.conf
```

The `name_servers` field must be altered in order to truly alter your
resolv.conf:

``` conf
name_servers="127.0.0.1"
```

#### dhcpcd

dhcpcd may try to overwrite your resolv.conf with whatever nameservers are
advertised by your router (usually your ISP's nameservers). To prevent this,
`/etc/dhcpcd.conf` must be modified:

``` sh
$ sudo vi /etc/dhcpcd.conf
```

In the default config, you may see a line which looks like:

``` conf
option domain_name_servers, domain_name, domain_search, host_name
```

We want to remove `domain_name_servers`, `domain_name`, and `domain_search`.

``` conf
option host_name
```

#### NetworkManager

Likewise, NetworkManager has similar behavior to dhcpcd. To prevent it from
tainting your resolv.conf, `/etc/NetworkManager/NetworkManager.conf` must be
altered:

``` sh
$ sudo vi /etc/NetworkManager/NetworkManager.conf
```

The default `NetworkManager.conf` is usually empty, but we need to add a `dns`
option under the `[main]` section, resulting in a configuration like:

``` conf
[main]
dns=none
```

Note that NetworkManager will also [check][nm-1] [connectivity][nm-2] by
resolving a domain. This can cause issues with hnsd. Disable with:

``` conf
[connectivity]
interval=604800
```

### Docker

**Windows users:** your system may alter the "end of line" characters in certain files
that will break the build inside docker. To prevent this, add this option to your
git global configuraiton before cloning this repo:

```bash
 $ git config --global core.autocrlf input
 ```

#### Building an image

To build a Docker image with the name `hnsd`, run:

```bash
$ docker build -t hnsd .
```

#### Running a container

To create and run a container named `hnsd`, run:

```bash
$ docker create \
  --name=hnsd \
  --publish=127.0.0.1:53:53/udp \
  --restart=unless-stopped \
  hnsd -r 0.0.0.0:53
```

```bash
$ docker start hnsd
```

To check the `hnsd` container if it runs correctly

```bash
$ docker ps -a
```

#### Stopping a container

To stop a container named `hnsd`, run:

```bash
$ docker stop hnsd
```

### OpenWRT

To build hnsd as an OpenWRT package you'll need to rename `openwrt_Makefile` to `Makefile` 
and put it in `your_openwrt_dir/package/net/hnsd` before building.
Then you can use your `menuconfig` and select it.  
Or you can use this command if you want to build on your SDK this package only:

```bash
$ make package/net/hnsd/compile V=s
```

Please keep in mind that `hnsd` needs `libunbound` and all of its dependencies
such as `libsodium, libmnl, libevent2(all packs), libpthread, libnghttp2, python3-base,libprotobuf-c`
and some of them are reqired to be installed manually. 

## Usage

``` sh
$ hnsd [options]
```

**Reccomended usage:**

```sh
mkdir ~/.hnsd
hnsd -t -x ~/.hnsd
```

This will start hnsd sync from the hard-coded checkpoint and continue to save
its own checkpoints to disk to ensure rapid chain sync on future boots.

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

-a, --user-agent <string>
  Add supplemental user agent string in p2p version message.

-t, --checkpoint
  Start chain sync from checkpoint.

-x, --prefix <directory name>
  Write/read state to/from disk in given directory.
  
-d, --daemon
  Fork and background the process.

-h, --help
  Help message.
```

## Testing

### Unit tests

The `make` command will output two binaries into the root directory: `hnsd`
and `test_hnsd`, which is compiled from unit tests in the `test/` directory.
Run the tests with `./test_hnsd`.

### Integration tests

The `integration/` directory contains a nodejs package that installs hsd and
runs a bmocha test suite. `hnsd` is run using `child_process.spawn()` and tested
by making DNS queries to its open ports.

`hnsd` MUST be built in regtest mode: `./configure --with-network=regtest`

Build and run the integration tests (requires nodejs >= v16):

```
make e2e
```

or:

```
npm --prefix ./integration install
npm --prefix ./integration run test
```

## License

- Copyright (c) 2018, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[hns]: https://handshake.org/
[libuv]: https://libuv.org/
[libunbound]: https://www.unbound.net/
[nm-1]: https://bbs.archlinux.org/viewtopic.php?id=223720
[nm-2]: https://bbs.archlinux.org/viewtopic.php?id=225310
