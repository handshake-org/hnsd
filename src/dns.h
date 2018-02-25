#ifndef _HSK_DNS_H
#define _HSK_DNS_H

#include <stdint.h>
#include <stdbool.h>

typedef struct hsk_dns_question_s {
  char *name;
  uint16_t type;
  uint16_t class;
  struct hsk_dns_question_s *next;
} hsk_dns_question_t;

typedef struct hsk_dns_record_s {
  char *name;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  void *rd;
  struct hsk_dns_record_s *next;
} hsk_dns_record_t;

typedef struct {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
  hsk_dns_question_t *question;
  hsk_dns_record_t *answer;
  hsk_dns_record_t *authority;
  hsk_dns_record_t *additional;
} hsk_dns_message_t;

typedef struct hsk_dns_text_s {
  uint8_t data_len;
  uint8_t *data;
  struct hsk_dns_text_s *next;
} hsk_dns_text_t;

typedef struct {
  size_t rd_len;
  uint8_t *rd;
} hsk_dns_unknown_rd_t;

typedef struct {
  char *ns;
  char *mbox;
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
  char *target;
} hsk_dns_cname_rd_t;

typedef struct {
  char *target;
} hsk_dns_dname_rd_t;

typedef struct {
  char *ns;
} hsk_dns_ns_rd_t;

typedef struct {
  uint16_t preference;
  char *mx;
} hsk_dns_mx_rd_t;

typedef struct {
  char *ptr;
} hsk_dns_ptr_rd_t;

typedef struct {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
  char *target;
} hsk_dns_srv_rd_t;

typedef struct {
  hsk_dns_text_t *text;
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

typedef struct {
  uint8_t algorithm;
  uint8_t type;
  size_t fingerprint_len;
  uint8_t *fingerprint;
} hsk_dns_sshfp_rd_t;

typedef struct {
  size_t public_key_len;
  uint8_t *public_key;
} hsk_dns_openpgpkey_rd_t;

typedef struct {
  char *target;
  uint8_t type;
  hsk_dns_record_t *current;
} hsk_dns_iterator_t;

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
#define HSK_DNS_FORMATERROR 1 // Format Error
#define HSK_DNS_SERVERFAILURE 2 // Server Failure
#define HSK_DNS_NXDOMAIN 3 // Non-Existent Domain
#define HSK_DNS_NOTIMPLEMENTED 4 // Not Implemented
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
// #define HSK_DNS_NONE 0
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
#define HSK_DNS_URI 256
#define HSK_DNS_CAA 257
#define HSK_DNS_AVC 258 // proposed
#define HSK_DNS_TKEY 249
#define HSK_DNS_TSIG 250
#define HSK_DNS_IXFR 251 // unimpl (pseudo-record)
#define HSK_DNS_AXFR 252 // unimpl (pseudo-record)
#define HSK_DNS_MAILB 253 // experimental unimpl (qtype)
#define HSK_DNS_MAILA 254 // obsolete unimpl (qtype)
#define HSK_DNS_ANY 255 // impl (qtype)
#define HSK_DNS_TA 32768
#define HSK_DNS_DLV 32769
#define HSK_DNS_RESERVED 65535 // unimpl

// Classes
#define HSK_DNS_INET 1
#define HSK_DNS_CSNET 2
#define HSK_DNS_CHAOS 3
#define HSK_DNS_HESIOD 4
#define HSK_DNS_NONE 254
#define HSK_DNS_ANY 255

// EDNS flags
#define HSK_DNS_DO 1 << 15 // DNSSEC OK

// EDNS Options
#define HSK_DNS_LLQ 1 // Long Lived Queries
#define HSK_DNS_UL 2 // Update Lease Draft
#define HSK_DNS_NSID 3 // Nameserver Identifier
#define HSK_DNS_DAU 5 // DNSSEC Algorithm Understood
#define HSK_DNS_DHU 6 // DS Hash Understood
#define HSK_DNS_N3U 7 // NSEC3 Hash Understood
#define HSK_DNS_SUBNET 8 // Client Subnet
#define HSK_DNS_EXPIRE 9 // Expire
#define HSK_DNS_COOKIE 10 // Cookie
#define HSK_DNS_TCPKEEPALIVE 11 // TCP Keep-Alive
#define HSK_DNS_PADDING 12 // Padding
#define HSK_DNS_LOCALSTART 65001 // Beginning of range reserved for local/experimental use
#define HSK_DNS_LOCALEND 65534 // End of range reserved for local/experimental use
#endif
