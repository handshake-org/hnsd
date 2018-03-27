#ifndef _HSK_DNSSEC_H
#define _HSK_DNSSEC_H

#include <stdint.h>
#include "dns.h"

hsk_dns_rr_t *
hsk_dnssec_get_dnskey(void);

hsk_dns_rr_t *
hsk_dnssec_get_ds(void);

bool
hsk_dnssec_sign(hsk_dns_rrs_t *rrs, uint16_t type);

// priv: 1c74c825c5b0f08cf6be846bfc93c423f03e3e1f6202fb2d96474b1520bbafad
// cpub: 034fd714449d8cfcccfdaba52c64d63e3aca72be3f94bfeb60aeb5a42ed3d0c205
static const uint8_t hsk_dnssec_ksk[] = ""
  "\x1c\x74\xc8\x25\xc5\xb0\xf0\x8c\xf6\xbe\x84\x6b\xfc\x93\xc4\x23"
  "\xf0\x3e\x3e\x1f\x62\x02\xfb\x2d\x96\x47\x4b\x15\x20\xbb\xaf\xad";

// priv: 54276ff8604a3494c5c76d6651f14b289c7253ba636be4bfd7969308f48da47d
// cpub: 032399cfb3a72515ad609f09fd22954319d24b7c438dce00f535c7ee13010856e2
static const uint8_t hsk_dnssec_zsk[] = ""
  "\x54\x27\x6f\xf8\x60\x4a\x34\x94\xc5\xc7\x6d\x66\x51\xf1\x4b\x28"
  "\x9c\x72\x53\xba\x63\x6b\xe4\xbf\xd7\x96\x93\x08\xf4\x8d\xa4\x7d";

// priv: f91ec53991a3f23ef097182086a7efaaa5339ef659c1402afda5d947e29579ca
// cpub: 025c27db9326fea9e6da237b02c4b08b076a87bd32ffa9cf4f5b09baba916775fe
static const uint8_t hsk_dnssec_revoke[] = ""
  "\xf9\x1e\xc5\x39\x91\xa3\xf2\x3e\xf0\x97\x18\x20\x86\xa7\xef\xaa"
  "\xa5\x33\x9e\xf6\x59\xc1\x40\x2a\xfd\xa5\xd9\x47\xe2\x95\x79\xca";

#endif
