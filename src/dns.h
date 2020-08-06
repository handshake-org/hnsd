#ifndef _HSK_DNS_H
#define _HSK_DNS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "map.h"

typedef struct hsk_dns_rr_s {
  char name[256];
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  void *rd;
} hsk_dns_rr_t;

typedef hsk_dns_rr_t hsk_dns_qs_t;

typedef struct hsk_dns_rrs_s {
  size_t size;
  hsk_dns_rr_t *items[255];
} hsk_dns_rrs_t;

typedef struct hsk_dns_msg_s {
  uint16_t id;
  uint8_t opcode;
  uint16_t code;
  uint16_t flags;
  hsk_dns_rrs_t qd;
  hsk_dns_rrs_t an;
  hsk_dns_rrs_t ns;
  hsk_dns_rrs_t ar;
  struct {
    bool enabled;
    uint8_t version;
    uint16_t flags;
    uint16_t size;
    uint8_t code;
    size_t rd_len;
    uint8_t *rd;
  } edns;
} hsk_dns_msg_t;

typedef struct hsk_dns_txt_s {
  uint8_t data_len;
  uint8_t data[255];
} hsk_dns_txt_t;

typedef struct hsk_dns_txts_s {
  size_t size;
  hsk_dns_txt_t *items[255];
} hsk_dns_txts_t;

typedef struct {
  size_t rd_len;
  uint8_t *rd;
} hsk_dns_unknown_rd_t;

typedef struct {
  char ns[256];
  char mbox[256];
  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t minttl;
} hsk_dns_soa_rd_t;

typedef struct {
  uint8_t addr[4];
} hsk_dns_a_rd_t;

typedef struct {
  uint8_t addr[16];
} hsk_dns_aaaa_rd_t;

typedef struct {
  uint8_t version;
  uint8_t size;
  uint8_t horiz_pre;
  uint8_t vert_pre;
  uint32_t latitude;
  uint32_t longitude;
  uint32_t altitude;
} hsk_dns_loc_rd_t;

typedef struct {
  char target[256];
} hsk_dns_cname_rd_t;

typedef struct {
  char target[256];
} hsk_dns_dname_rd_t;

typedef struct {
  char ns[256];
} hsk_dns_ns_rd_t;

typedef struct {
  uint16_t preference;
  char mx[256];
} hsk_dns_mx_rd_t;

typedef struct {
  char ptr[256];
} hsk_dns_ptr_rd_t;

typedef struct {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  char target[256];
} hsk_dns_srv_rd_t;

typedef struct {
  hsk_dns_txts_t txts;
} hsk_dns_txt_rd_t;

typedef struct {
  uint16_t key_tag;
  uint8_t algorithm;
  uint8_t digest_type;
  size_t digest_len;
  uint8_t *digest;
} hsk_dns_ds_rd_t;

typedef struct {
  uint8_t usage;
  uint8_t selector;
  uint8_t matching_type;
  size_t certificate_len;
  uint8_t *certificate;
} hsk_dns_tlsa_rd_t;

#define hsk_dns_smimea_rd_t hsk_dns_tlsa_rd_t

typedef struct {
  uint8_t algorithm;
  uint8_t digest_type;
  size_t fingerprint_len;
  uint8_t *fingerprint;
} hsk_dns_sshfp_rd_t;

typedef struct {
  size_t pubkey_len;
  uint8_t *pubkey;
} hsk_dns_openpgpkey_rd_t;

typedef struct {
  size_t rd_len;
  uint8_t *rd;
} hsk_dns_opt_rd_t;

typedef struct {
  uint16_t flags;
  uint8_t protocol;
  uint8_t algorithm;
  size_t pubkey_len;
  uint8_t *pubkey;
} hsk_dns_dnskey_rd_t;

typedef struct {
  uint16_t type_covered;
  uint8_t algorithm;
  uint8_t labels;
  uint32_t orig_ttl;
  uint32_t expiration;
  uint32_t inception;
  uint16_t key_tag;
  char signer_name[256];
  size_t signature_len;
  uint8_t *signature;
} hsk_dns_rrsig_rd_t;

typedef struct {
  uint16_t priority;
  uint16_t weight;
  uint8_t data_len;
  uint8_t data[255];
} hsk_dns_uri_rd_t;

typedef struct {
  char mbox[256];
  char txt[256];
} hsk_dns_rp_rd_t;

typedef struct {
  char next_domain[256];
  size_t type_map_len;
  uint8_t *type_map;
} hsk_dns_nsec_rd_t;

typedef struct {
  hsk_map_t map;
  uint8_t *msg;
} hsk_dns_cmp_t;

typedef struct {
  uint8_t *msg;
  size_t msg_len;
} hsk_dns_dmp_t;

// Constants
#define HSK_DNS_MAX_NAME 255
#define HSK_DNS_MAX_LABEL 63
#define HSK_DNS_MAX_SANITIZED 1009
#define HSK_DNS_MAX_LABELS 128
#define HSK_DNS_MAX_UDP 512
#define HSK_DNS_STD_EDNS 1280
#define HSK_DNS_MAX_EDNS 4096
#define HSK_DNS_MAX_TCP 65535

// Opcodes
#define HSK_DNS_QUERY 0
#define HSK_DNS_IQUERY 1
#define HSK_DNS_STATUS 2
#define HSK_DNS_NOTIFY 4
#define HSK_DNS_UPDATE 5

// Flags
#define HSK_DNS_QR (1 << 15) // query/response (response=1)
#define HSK_DNS_AA (1 << 10) // authoritative
#define HSK_DNS_TC (1 << 9) // truncated
#define HSK_DNS_RD (1 << 8) // recursion desired
#define HSK_DNS_RA (1 << 7) // recursion available
#define HSK_DNS_Z (1 << 6) // Z
#define HSK_DNS_AD (1 << 5) // authenticated data
#define HSK_DNS_CD (1 << 4) // checking disabled

// Errors
#define HSK_DNS_NOERROR 0 // No Error
#define HSK_DNS_SUCCESS 0 // No Error
#define HSK_DNS_FORMERR 1 // Format Error
#define HSK_DNS_SERVFAIL 2 // Server Failure
#define HSK_DNS_NXDOMAIN 3 // Non-Existent Domain
#define HSK_DNS_NOTIMP 4 // Not Implemented
#define HSK_DNS_REFUSED 5 // Query Refused
#define HSK_DNS_YXDOMAIN 6 // Name Exists when it should not
#define HSK_DNS_YXRRSET 7 // RR Set Exists when it should not
#define HSK_DNS_NXRRSET 8 // RR Set that should exist does not
#define HSK_DNS_NOTAUTH 9 // Server Not Authoritative for zone
#define HSK_DNS_NOTZONE 10 // Name not contained in zone
#define HSK_DNS_BADSIG 16 // TSIG Signature Failure
#define HSK_DNS_BADVERS 16 // Bad OPT Version
#define HSK_DNS_BADKEY 17 // Key not recognized
#define HSK_DNS_BADTIME 18 // Signature out of time window
#define HSK_DNS_BADMODE 19 // Bad TKEY Mode
#define HSK_DNS_BADNAME 20 // Duplicate key name
#define HSK_DNS_BADALG 21 // Algorithm not supported
#define HSK_DNS_BADTRUNC 22 // Bad Truncation
#define HSK_DNS_BADCOOKIE 23 // Bad/missing Server Cookie

// Records
#define HSK_DNS_UNKNOWN 0
#define HSK_DNS_A 1
#define HSK_DNS_NS 2
#define HSK_DNS_MD 3 // obsolete
#define HSK_DNS_MF 4 // obsolete
#define HSK_DNS_CNAME 5
#define HSK_DNS_SOA 6
#define HSK_DNS_MB 7 // experimental
#define HSK_DNS_MG 8 // experimental
#define HSK_DNS_MR 9 // experimental
#define HSK_DNS_NULL 10 // obsolete
#define HSK_DNS_WKS 11 // deprecated
#define HSK_DNS_PTR 12
#define HSK_DNS_HINFO 13 // not-in-use
#define HSK_DNS_MINFO 14 // experimental
#define HSK_DNS_MX 15
#define HSK_DNS_TXT 16
#define HSK_DNS_RP 17
#define HSK_DNS_AFSDB 18
#define HSK_DNS_X25 19 // not-in-use
#define HSK_DNS_ISDN 20 // not-in-use
#define HSK_DNS_RT 21 // not-in-use
#define HSK_DNS_NSAP 22 // not-in-use
#define HSK_DNS_NSAPPTR 23 // not-in-use
#define HSK_DNS_SIG 24 // obsolete
#define HSK_DNS_KEY 25 // obsolete
#define HSK_DNS_PX 26 // not-in-use
#define HSK_DNS_GPOS 27 // deprecated
#define HSK_DNS_AAAA 28
#define HSK_DNS_LOC 29
#define HSK_DNS_NXT 30 // obsolete
#define HSK_DNS_EID 31 // not-in-use
#define HSK_DNS_NB 32 // obsolete
#define HSK_DNS_NIMLOC 32 // not-in-use
#define HSK_DNS_NBSTAT 33 // obsolete
#define HSK_DNS_SRV 33
#define HSK_DNS_ATMA 34 // not-in-use
#define HSK_DNS_NAPTR 35
#define HSK_DNS_KX 36
#define HSK_DNS_CERT 37
#define HSK_DNS_A6 38 // historic
#define HSK_DNS_DNAME 39
#define HSK_DNS_SINK 40 // unimpl (joke?)
#define HSK_DNS_OPT 41 // impl (pseudo-record edns)
#define HSK_DNS_APL 42 // not-in-use
#define HSK_DNS_DS 43
#define HSK_DNS_SSHFP 44
#define HSK_DNS_IPSECKEY 45
#define HSK_DNS_RRSIG 46
#define HSK_DNS_NSEC 47
#define HSK_DNS_DNSKEY 48
#define HSK_DNS_DHCID 49
#define HSK_DNS_NSEC3 50
#define HSK_DNS_NSEC3PARAM 51
#define HSK_DNS_TLSA 52
#define HSK_DNS_SMIMEA 53
#define HSK_DNS_HIP 55
#define HSK_DNS_NINFO 56 // proposed
#define HSK_DNS_RKEY 57 // proposed
#define HSK_DNS_TALINK 58 // proposed
#define HSK_DNS_CDS 59
#define HSK_DNS_CDNSKEY 60
#define HSK_DNS_OPENPGPKEY 61
#define HSK_DNS_CSYNC 62
#define HSK_DNS_SPF 99 // obsolete
#define HSK_DNS_UINFO 100 // obsolete
#define HSK_DNS_UID 101 // obsolete
#define HSK_DNS_GID 102 // obsolete
#define HSK_DNS_UNSPEC 103 // obsolete
#define HSK_DNS_NID 104
#define HSK_DNS_L32 105
#define HSK_DNS_L64 106
#define HSK_DNS_LP 107
#define HSK_DNS_EUI48 108
#define HSK_DNS_EUI64 109
#define HSK_DNS_TKEY 249
#define HSK_DNS_TSIG 250
#define HSK_DNS_IXFR 251 // unimpl (pseudo-record)
#define HSK_DNS_AXFR 252 // unimpl (pseudo-record)
#define HSK_DNS_MAILB 253 // experimental unimpl (qtype)
#define HSK_DNS_MAILA 254 // obsolete unimpl (qtype)
#define HSK_DNS_ANY 255 // impl (qtype)
#define HSK_DNS_URI 256
#define HSK_DNS_CAA 257
#define HSK_DNS_AVC 258 // proposed
#define HSK_DNS_DOA 259 // proposed
#define HSK_DNS_TA 32768
#define HSK_DNS_DLV 32769
#define HSK_DNS_RESERVED 65535 // unimpl

// Classes
#define HSK_DNS_IN 1
#define HSK_DNS_CH 3
#define HSK_DNS_HS 4
#define HSK_DNS_NONE 254
// #define HSK_DNS_ANY 255

// EDNS flags
#define HSK_DNS_DO (1 << 15) // DNSSEC OK

// EDNS Options
#define HSK_DNS_OPT_RESERVED 0 // Reserved
#define HSK_DNS_OPT_LLQ 1 // Long Lived Queries
#define HSK_DNS_OPT_UL 2 // Update Lease Draft
#define HSK_DNS_OPT_NSID 3 // Nameserver Identifier
#define HSK_DNS_OPT_DAU 5 // DNSSEC Algorithm Understood
#define HSK_DNS_OPT_DHU 6 // DS Hash Understood
#define HSK_DNS_OPT_N3U 7 // NSEC3 Hash Understood
#define HSK_DNS_OPT_SUBNET 8 // Client Subnet
#define HSK_DNS_OPT_EXPIRE 9 // Expire
#define HSK_DNS_OPT_COOKIE 10 // Cookie
#define HSK_DNS_OPT_TCPKEEPALIVE 11 // TCP Keep-Alive
#define HSK_DNS_OPT_PADDING 12 // Padding
#define HSK_DNS_OPT_CHAIN 13 // Chain
#define HSK_DNS_OPT_KEYTAG 14 // Key Tag
#define HSK_DNS_OPT_DEVICEID 26946 // Device ID
#define HSK_DNS_OPT_LOCAL 65001 // Beginning of local/experimental use
#define HSK_DNS_OPT_LOCALSTART 65001 // Beginning of local/experimental use
#define HSK_DNS_OPT_LOCALEND 65534 // End of local/experimental use

void
hsk_dns_msg_init(hsk_dns_msg_t *msg);

void
hsk_dns_msg_uninit(hsk_dns_msg_t *msg);

hsk_dns_msg_t *
hsk_dns_msg_alloc(void);

void
hsk_dns_msg_free(hsk_dns_msg_t *msg);

bool
hsk_dns_msg_decode(const uint8_t *data, size_t data_len, hsk_dns_msg_t **msg);

int
hsk_dns_msg_write(const hsk_dns_msg_t *msg, uint8_t **data);

int
hsk_dns_msg_size(const hsk_dns_msg_t *msg);

bool
hsk_dns_msg_encode(const hsk_dns_msg_t *msg, uint8_t **data, size_t *data_len);

bool
hsk_dns_msg_truncate(uint8_t *msg, size_t msg_len, size_t max, size_t *len);

bool
hsk_dns_msg_read(uint8_t **data, size_t *data_len, hsk_dns_msg_t *msg);

void
hsk_dns_rrs_init(hsk_dns_rrs_t *rrs);

void
hsk_dns_rrs_uninit(hsk_dns_rrs_t *rrs);

hsk_dns_rrs_t *
hsk_dns_rrs_alloc(void);

void
hsk_dns_rrs_free(hsk_dns_rrs_t *rrs);

size_t
hsk_dns_rrs_unshift(hsk_dns_rrs_t *rrs, hsk_dns_rr_t *rr);

hsk_dns_rr_t *
hsk_dns_rrs_shift(hsk_dns_rrs_t *rrs);

size_t
hsk_dns_rrs_push(hsk_dns_rrs_t *rrs, hsk_dns_rr_t *rr);

hsk_dns_rr_t *
hsk_dns_rrs_pop(hsk_dns_rrs_t *rrs);

hsk_dns_rr_t *
hsk_dns_rrs_get(hsk_dns_rrs_t *rrs, int index);

size_t
hsk_dns_rrs_set(hsk_dns_rrs_t *rrs, int index, hsk_dns_rr_t *rr);

void
hsk_dns_qs_init(hsk_dns_qs_t *qs);

void
hsk_dns_qs_uninit(hsk_dns_qs_t *qs);

hsk_dns_qs_t *
hsk_dns_qs_alloc(void);

void
hsk_dns_qs_free(hsk_dns_qs_t *qs);

void
hsk_dns_qs_set(hsk_dns_qs_t *qs, const char *name, uint16_t type);

int
hsk_dns_qs_write(const hsk_dns_qs_t *qs, uint8_t **data, hsk_dns_cmp_t *cmp);

bool
hsk_dns_qs_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_dns_qs_t *qs
);

void
hsk_dns_rr_init(hsk_dns_rr_t *rr);

void
hsk_dns_rr_uninit(hsk_dns_rr_t *rr);

hsk_dns_rr_t *
hsk_dns_rr_alloc(void);

hsk_dns_rr_t *
hsk_dns_rr_create(uint16_t type);

void
hsk_dns_rr_free(hsk_dns_rr_t *rr);

bool
hsk_dns_rr_set_name(hsk_dns_rr_t *rr, const char *name);

int
hsk_dns_rr_write(const hsk_dns_rr_t *rr, uint8_t **data, hsk_dns_cmp_t *cmp);

int
hsk_dns_rr_size(const hsk_dns_rr_t *rr);

bool
hsk_dns_rr_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  hsk_dns_rr_t *rr
);

bool
hsk_dns_rr_encode(const hsk_dns_rr_t *rr, uint8_t **data, size_t *data_len);

bool
hsk_dns_rr_decode(const uint8_t *data, size_t data_len, hsk_dns_rr_t **out);

hsk_dns_rr_t *
hsk_dns_rr_clone(const hsk_dns_rr_t *rr);

void
hsk_dns_rd_init(void *rd, uint16_t type);

void *
hsk_dns_rd_alloc(uint16_t type);

void
hsk_dns_rd_uninit(void *rd, uint16_t type);

void
hsk_dns_rd_free(void *rd, uint16_t type);

int
hsk_dns_rd_write(
  const void *rd,
  uint16_t type,
  uint8_t **data,
  hsk_dns_cmp_t *cmp
);

int
hsk_dns_rd_size(const void *rd, uint16_t type);

bool
hsk_dns_rd_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  void *rd,
  uint16_t type
);

bool
hsk_dns_rd_encode(
  const void *rd,
  uint16_t type,
  uint8_t **data,
  size_t *data_len
);

bool
hsk_dns_rd_decode(
  const uint8_t *data,
  size_t data_len,
  uint16_t type,
  void **out
);

void
hsk_dns_txts_init(hsk_dns_txts_t *txts);

void
hsk_dns_txts_uninit(hsk_dns_txts_t *txts);

hsk_dns_txts_t *
hsk_dns_txts_alloc(void);

void
hsk_dns_txts_free(hsk_dns_txts_t *txts);

size_t
hsk_dns_txts_unshift(hsk_dns_txts_t *txts, hsk_dns_txt_t *txt);

hsk_dns_txt_t *
hsk_dns_txts_shift(hsk_dns_txts_t *txts);

size_t
hsk_dns_txts_push(hsk_dns_txts_t *txts, hsk_dns_txt_t *txt);

hsk_dns_txt_t *
hsk_dns_txts_pop(hsk_dns_txts_t *txts);

hsk_dns_txt_t *
hsk_dns_txts_get(hsk_dns_txts_t *txts, int index);

size_t
hsk_dns_txts_set(hsk_dns_txts_t *txts, int index, hsk_dns_txt_t *txt);

void
hsk_dns_txt_init(hsk_dns_txt_t *txt);

void
hsk_dns_txt_uninit(hsk_dns_txt_t *txt);

hsk_dns_txt_t *
hsk_dns_txt_alloc(void);

void
hsk_dns_txt_free(hsk_dns_txt_t *txt);

int
hsk_dns_name_parse(
  uint8_t **data_,
  size_t *data_len_,
  const hsk_dns_dmp_t *dmp,
  char *name
);

int
hsk_dns_name_pack(const char *name, uint8_t *data);

int
hsk_dns_name_write(const char *name, uint8_t **data, hsk_dns_cmp_t *cmp);

bool
hsk_dns_name_read(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  char *name
);

int
hsk_dns_name_read_size(
  const uint8_t *data,
  size_t data_len,
  const hsk_dns_dmp_t *dmp
);

bool
hsk_dns_name_alloc(
  uint8_t **data,
  size_t *data_len,
  const hsk_dns_dmp_t *dmp,
  char **name
);

bool
hsk_dns_name_dirty(const char *name);

void
hsk_dns_name_sanitize(const char *name, char *out);

bool
hsk_dns_name_verify(const char *name);

bool
hsk_dns_name_is_fqdn(const char *name);

int
hsk_dns_name_cmp(const char *a, const char *b);

/**
 * Returns: number of labels found in the name
 * In:      name:   pointer to string containing full domain name
            size:   max number of labels expected in the name
 * Out:     labels: if present, array is filled with offset (in bytes)
 *                  of starting point of each label in name
 */
int
hsk_dns_label_split(const char *name, uint8_t *labels, size_t size);

/**
 * Returns: number of labels in the name
 * In:      name:   pointer to string containing full domain name
 */
int
hsk_dns_label_count(const char *name);

/**
 * Returns: length of string from requested label through end of name
 * In:      name:   pointer to string containing full domain name
 *          labels: pointer to array of offsets of each label in name
 *          count:  number of labels in the name
 *          index:  index of starting label in name to return
 *                  (-1 = last label, TLD)
 * Out:     ret:    pointer to string to be filled with name from
 *                  specified label through end of name
 */
int
hsk_dns_label_from2(
  const char *name,
  uint8_t *labels,
  int count,
  int index,
  char *ret
);

/**
 * Returns: length of string from requested label through end of name
 * In:      name:   pointer to string containing full domain name
 *          index:  index of starting label in name to return
 *                  (-1 = last label, TLD)
 * Out:     ret:    pointer to string to be filled with name from
 *                  specified label through end of name
 */
int
hsk_dns_label_from(const char *name, int index, char *ret);

/**
 * Returns: length of requested label
 * In:      name:   pointer to string containing full domain name
 *          labels: pointer to array of offsets of each label in name
 *          count:  number of labels in the name
 *          index:  index of label in name to return (-1 = last label, TLD)
 * Out:     ret:    pointer to string to be filled with requested label
 */
int
hsk_dns_label_get2(
  const char *name,
  uint8_t *labels,
  int count,
  int index,
  char *ret
);

/**
 * Returns: length of requested label
 * In:      name:   pointer to string containing full domain name
 *          index:  index of label in name to return (-1 = last label, TLD)
 * Out:     ret:    pointer to string to be filled with requested label
 */
int
hsk_dns_label_get(const char *name, int index, char *ret);

bool
hsk_dns_label_decode_srv(const char *name, char *protocol, char *service);

bool
hsk_dns_label_is_srv(const char *name);

bool
hsk_dns_label_decode_tlsa(const char *name, char *protocol, uint16_t *port);

bool
hsk_dns_label_is_tlsa(const char *name);

bool
hsk_dns_label_decode_smimea(const char *name, uint8_t *hash);

bool
hsk_dns_label_is_smimea(const char *name);

bool
hsk_dns_label_decode_openpgpkey(const char *name, uint8_t *hash);

bool
hsk_dns_label_is_openpgpkey(const char *name);

/*
 * DNSSEC
 */

long
hsk_dns_dnskey_keytag(const hsk_dns_dnskey_rd_t *rd);

bool
hsk_dns_rrsig_tbs(hsk_dns_rrsig_rd_t *rrsig, uint8_t **data, size_t *data_len);

hsk_dns_rr_t *
hsk_dns_dnskey_create(const char *zone, const uint8_t *priv, bool ksk);

hsk_dns_rr_t *
hsk_dns_ds_create(const hsk_dns_rr_t *key);

bool
hsk_dns_sign_type(
  hsk_dns_rrs_t *rrs,
  uint16_t type,
  const hsk_dns_rr_t *key,
  const uint8_t *priv
);

hsk_dns_rr_t *
hsk_dns_sign_rrset(
  hsk_dns_rrs_t *rrset,
  const hsk_dns_rr_t *key,
  const uint8_t *priv
);

bool
hsk_dns_sign_rrsig(
  hsk_dns_rrs_t *rrset,
  hsk_dns_rr_t *sig,
  const uint8_t *priv
);

bool
hsk_dns_sighash(hsk_dns_rrs_t *rrset, hsk_dns_rr_t *sig, uint8_t *hash);

bool
hsk_dns_msg_clean(hsk_dns_msg_t *msg, uint16_t type);

bool
hsk_dns_rrs_clean(hsk_dns_rrs_t *rrs, uint16_t type);

/*
 * Helpers
 */

bool
hsk_dns_is_subdomain(const char *parent, const char *child);

#endif
