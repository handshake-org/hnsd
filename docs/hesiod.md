# hnsd Hesiod API

hnsd does not have an http server, but we can use special DNS requests to query
the node for metadata about the blockchain and network. These queries are made
using the Hesiod (`HS`) class, as opposed to the usual Internet (`IN`) class.
[Hesiod service](https://en.wikipedia.org/wiki/Hesiod_(name_service)) was
developed in the 1980s and many legacy DNS tools like `dig` support it.
The abbreviation "HS" is a nice coincidence for Handshake.

Hesiod is only supported by the hnsd root name server, and currently only
responds to requests from local connections. Queries are made by requesting TXT
records of class HS using a domain name tree that represents a hierarchical
data structure (like a JSON object).

## Implied wildcard (`*.domain`)

All HS requests are preceded by an implied wildcard. This means that if a
requested name has any subdomains, they will all be returned, recursively.
Because of this a request for `HS TXT .` will return ALL available data
from the API.

## Ports

Reminder the root nameserver ports for each HNS network:

| Network |  Port  |
|---------|--------|
| main    | `5349` |
| testnet | `15349`|
| regtest | `25349`|
| simnet  | `35349`|

## Quick Examples

Get the current block height (mainnet):

```
$ dig @127.0.0.1 -p 5349 HS TXT height.tip.chain.hnsd +short
"70000"
```

Get the number of peers (mainnet):

```
$ dig @127.0.0.1 -p 5349 HS TXT size.pool.hnsd +short
"8"
```

## Big examples

Get all chain tip data (mainnet):

```
$ dig @127.0.0.1 -p 5349 HS TXT tip.chain.hnsd

...

;; ANSWER SECTION:
hash.tip.chain.hnsd.    0       HS      TXT     "0000000000000007cde5b551d04468b421d05a7ce862e7e50cff3c397af315ea"
height.tip.chain.hnsd.  0       HS      TXT     "145921"
time.tip.chain.hnsd.    0       HS      TXT     "1668181113"

...
```

Get information about connected peers (mainnet):

```
$ dig @127.0.0.1 -p 5349 HS TXT peers.pool.hnsd

...

;; ANSWER SECTION:
host.0.peers.pool.hnsd. 0       HS      TXT     "159.69.46.23:44806"
agent.0.peers.pool.hnsd. 0      HS      TXT     "/hsd:4.0.0/"
headers.0.peers.pool.hnsd. 0    HS      TXT     "20000"
proofs.0.peers.pool.hnsd. 0     HS      TXT     "0"
state.0.peers.pool.hnsd. 0      HS      TXT     "HSK_STATE_HANDSHAKE"

...
```

## Complete HS API object

```
.: {
  hnsd: {
    chain: {
      tip: {
        hash:   `32 byte hex string`,
        height: `unsigned int`,
        time:   `unsigned int`
      },
      synced:   `boolean`,
      progress: `float`
    },
    pool: {
      size:     `unsigned int`,
      [index].peers: [
        {
          host:    `string`,
          agent:   `string`,
          headers: `unsigned int`, // number of headers received from peer
          proofs:  `unsigned int`, // number of urkel proofs received from peer
          state:   `string`        // connection status, see pool.h
        }
      ]
    }
  }
}
```

