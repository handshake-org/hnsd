#ifndef _HSK_MSG_H
#define _HSK_MSG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct _dns_question {
  char *name;
  uint16_t type;
  uint16_t class;
  struct _dns_question *next;
} dns_question_t;

typedef struct _dns_record {
  char *name;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  void *rd;
  struct _dns_record *next;
} dns_record_t;

typedef struct {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
  dns_question_t *question;
  dns_record_t *answer;
  dns_record_t *authority;
  dns_record_t *additional;
} dns_message_t;

typedef struct _dns_text {
  uint8_t data_len;
  uint8_t *data;
  struct _dns_text *next;
} dns_text_t;

typedef struct {
  size_t rd_len;
  uint8_t *rd;
} dns_unknown_rd_t;

typedef struct {
  char *ns;
  char *mbox;
  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t minttl;
} dns_soa_rd_t;

typedef struct {
  uint8_t addr[4];
} dns_a_rd_t;

typedef struct {
  uint8_t addr[16];
} dns_aaaa_rd_t;

typedef struct {
  char *target;
} dns_cname_rd_t;

typedef struct {
  char *target;
} dns_dname_rd_t;

typedef struct {
  char *ns;
} dns_ns_rd_t;

typedef struct {
  uint16_t preference;
  char *mx;
} dns_mx_rd_t;

typedef struct {
  char *ptr;
} dns_ptr_rd_t;

typedef struct {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  char *target;
} dns_srv_rd_t;

typedef struct {
  dns_text_t *text;
} dns_txt_rd_t;

typedef struct {
  uint16_t key_tag;
  uint8_t algorithm;
  uint8_t digest_type;
  size_t digest_len;
  uint8_t *digest;
} dns_ds_rd_t;

typedef struct {
  uint8_t usage;
  uint8_t selector;
  uint8_t matching_type;
  size_t certificate_len;
  uint8_t *certificate;
} dns_tlsa_rd_t;

typedef struct {
  uint8_t algorithm;
  uint8_t type;
  size_t fingerprint_len;
  uint8_t *fingerprint;
} dns_sshfp_rd_t;

typedef struct {
  size_t public_key_len;
  uint8_t *public_key;
} dns_openpgpkey_rd_t;

typedef struct {
  char *target;
  uint8_t type;
  dns_record_t *current;
} dns_iterator_t;

// Opcodes
#define DNS_QUERY 0
#define DNS_IQUERY 1
#define DNS_STATUS 2
#define DNS_NOTIFY 4
#define DNS_UPDATE 5

// Flags
#define DNS_QR 1 << 15 // query/response (response=1)
#define DNS_AA 1 << 10 // authoritative
#define DNS_TC 1 << 9  // truncated
#define DNS_RD 1 << 8  // recursion desired
#define DNS_RA 1 << 7  // recursion available
#define DNS_Z 1 << 6  // Z
#define DNS_AD 1 << 5  // authenticated data
#define DNS_CD 1 << 4  // checking disabled

// Errors
#define DNS_NOERROR 0 // No Error
#define DNS_SUCCESS 0 // No Error
#define DNS_FORMATERROR 1 // Format Error
#define DNS_SERVERFAILURE 2 // Server Failure
#define DNS_NAMEERROR 3 // Non-Existent Domain
#define DNS_NOTIMPLEMENTED 4 // Not Implemented
#define DNS_REFUSED 5 // Query Refused
#define DNS_YXDOMAIN 6 // Name Exists when it should not
#define DNS_YXRRSET 7 // RR Set Exists when it should not
#define DNS_NXRRSET 8 // RR Set that should exist does not
#define DNS_NOTAUTH 9 // Server Not Authoritative for zone
#define DNS_NOTZONE 10 // Name not contained in zone
#define DNS_BADSIG 16 // TSIG Signature Failure
#define DNS_BADVERS 16 // Bad OPT Version
#define DNS_BADKEY 17 // Key not recognized
#define DNS_BADTIME 18 // Signature out of time window
#define DNS_BADMODE 19 // Bad TKEY Mode
#define DNS_BADNAME 20 // Duplicate key name
#define DNS_BADALG 21 // Algorithm not supported
#define DNS_BADTRUNC 22 // Bad Truncation
#define DNS_BADCOOKIE 23 // Bad/missing Server Cookie

// Records
// #define DNS_NONE 0
#define DNS_A 1
#define DNS_NS 2
#define DNS_MD 3 // obsolete
#define DNS_MF 4 // obsolete
#define DNS_CNAME 5
#define DNS_SOA 6
#define DNS_MB 7 // experimental
#define DNS_MG 8 // experimental
#define DNS_MR 9 // experimental
#define DNS_NULL 10 // obsolete
#define DNS_WKS 11 // deprecated
#define DNS_PTR 12
#define DNS_HINFO 13 // not-in-use
#define DNS_MINFO 14 // experimental
#define DNS_MX 15
#define DNS_TXT 16
#define DNS_RP 17
#define DNS_AFSDB 18
#define DNS_X25 19 // not-in-use
#define DNS_ISDN 20 // not-in-use
#define DNS_RT 21 // not-in-use
#define DNS_NSAP 22 // not-in-use
#define DNS_NSAPPTR 23 // not-in-use
#define DNS_SIG 24 // obsolete
#define DNS_KEY 25 // obsolete
#define DNS_PX 26 // not-in-use
#define DNS_GPOS 27 // deprecated
#define DNS_AAAA 28
#define DNS_LOC 29
#define DNS_NXT 30 // obsolete
#define DNS_EID 31 // not-in-use
#define DNS_NB 32 // obsolete
#define DNS_NIMLOC 32 // not-in-use
#define DNS_NBSTAT 33 // obsolete
#define DNS_SRV 33
#define DNS_ATMA 34 // not-in-use
#define DNS_NAPTR 35
#define DNS_KX 36
#define DNS_CERT 37
#define DNS_A6 38 // historic
#define DNS_DNAME 39
#define DNS_SINK 40 // unimpl (joke?)
#define DNS_OPT 41 // impl (pseudo-record edns)
#define DNS_APL 42 // not-in-use
#define DNS_DS 43
#define DNS_SSHFP 44
#define DNS_IPSECKEY 45
#define DNS_RRSIG 46
#define DNS_NSEC 47
#define DNS_DNSKEY 48
#define DNS_DHCID 49
#define DNS_NSEC3 50
#define DNS_NSEC3PARAM 51
#define DNS_TLSA 52
#define DNS_SMIMEA 53
#define DNS_HIP 55
#define DNS_NINFO 56 // proposed
#define DNS_RKEY 57 // proposed
#define DNS_TALINK 58 // proposed
#define DNS_CDS 59
#define DNS_CDNSKEY 60
#define DNS_OPENPGPKEY 61
#define DNS_CSYNC 62
#define DNS_SPF 99 // obsolete
#define DNS_UINFO 100 // obsolete
#define DNS_UID 101 // obsolete
#define DNS_GID 102 // obsolete
#define DNS_UNSPEC 103 // obsolete
#define DNS_NID 104
#define DNS_L32 105
#define DNS_L64 106
#define DNS_LP 107
#define DNS_EUI48 108
#define DNS_EUI64 109
#define DNS_URI 256
#define DNS_CAA 257
#define DNS_AVC 258 // proposed
#define DNS_TKEY 249
#define DNS_TSIG 250
#define DNS_IXFR 251 // unimpl (pseudo-record)
#define DNS_AXFR 252 // unimpl (pseudo-record)
#define DNS_MAILB 253 // experimental unimpl (qtype)
#define DNS_MAILA 254 // obsolete unimpl (qtype)
#define DNS_ANY 255 // impl (qtype)
#define DNS_TA 32768
#define DNS_DLV 32769
#define DNS_RESERVED 65535 // unimpl

// Classes
#define DNS_INET 1
#define DNS_CSNET 2
#define DNS_CHAOS 3
#define DNS_HESIOD 4
#define DNS_NONE 254
#define DNS_ANY 255

// EDNS flags
#define DNS_DO 1 << 15 // DNSSEC OK

// EDNS Options
#define DNS_LLQ 1 // Long Lived Queries
#define DNS_UL 2 // Update Lease Draft
#define DNS_NSID 3 // Nameserver Identifier
#define DNS_DAU 5 // DNSSEC Algorithm Understood
#define DNS_DHU 6 // DS Hash Understood
#define DNS_N3U 7 // NSEC3 Hash Understood
#define DNS_SUBNET 8 // Client Subnet
#define DNS_EXPIRE 9 // Expire
#define DNS_COOKIE 10 // Cookie
#define DNS_TCPKEEPALIVE 11 // TCP Keep-Alive
#define DNS_PADDING 12 // Padding
#define DNS_LOCALSTART 65001 // Beginning of range reserved for local/experimental use
#define DNS_LOCALEND 65534 // End of range reserved for local/experimental use
#endif
