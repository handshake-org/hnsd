#ifndef _HSK_RESOURCE_H
#define _HSK_RESOURCE_H

#define HSK_INET4 1
#define HSK_INET6 2
#define HSK_ONION 3
#define HSK_ONIONNG 4
#define HSK_NAME 5
#define HSK_GLUE 6
#define HSK_CANONICAL 7
#define HSK_DELEGATE 8
#define HSK_NS 9
#define HSK_SERVICE 10
#define HSK_URI 11
#define HSK_EMAIL 12
#define HSK_TEXT 13
#define HSK_LOCATION 14
#define HSK_MAGNET 15
#define HSK_DS 16
#define HSK_TLS 17
#define HSK_SMIME 18
#define HSK_SSH 19
#define HSK_PGP 20
#define HSK_ADDR 21
#define HSK_EXTRA 255

#include <stdint.h>
#include <stdbool.h>
#include "addr.h"
#include "dns.h"

// Records
typedef struct hsk_record_s {
  uint8_t type;
} hsk_record_t;

typedef struct hsk_target_s {
  uint8_t type;
  char name[256];
  uint8_t inet4[4];
  uint8_t inet6[16];
  uint8_t onion[33];
} hsk_target_t;

typedef struct hsk_host_record_s {
  uint8_t type;
  hsk_target_t target;
} hsk_host_record_t;

typedef hsk_host_record_t hsk_inet4_record_t;
typedef hsk_host_record_t hsk_inet6_record_t;
typedef hsk_host_record_t hsk_onion_record_t;
typedef hsk_host_record_t hsk_onionng_record_t;
typedef hsk_host_record_t hsk_name_record_t;
typedef hsk_host_record_t hsk_canonical_record_t;
typedef hsk_host_record_t hsk_delegate_record_t;
typedef hsk_host_record_t hsk_ns_record_t;

typedef struct hsk_service_record_s {
  uint8_t type;
  char service[256];
  char protocol[256];
  uint8_t priority;
  uint8_t weight;
  hsk_target_t target;
  uint16_t port;
} hsk_service_record_t;

// uri, email, text
typedef struct hsk_txt_record_s {
  uint8_t type;
  char text[256];
} hsk_txt_record_t;

typedef hsk_txt_record_t hsk_uri_record_t;
typedef hsk_txt_record_t hsk_email_record_t;
typedef hsk_txt_record_t hsk_text_record_t;

typedef struct hsk_location_record_s {
  uint8_t type;
  uint8_t version;
  uint8_t size;
  uint8_t horiz_pre;
  uint8_t vert_pre;
  uint32_t latitude;
  uint32_t longitude;
  uint32_t altitude;
} hsk_location_record_t;

typedef struct hsk_magnet_record_s {
  uint8_t type;
  char nid[256];
  size_t nin_len;
  uint8_t nin[64];
} hsk_magnet_record_t;

typedef struct hsk_ds_record_s {
  uint8_t type;
  uint16_t key_tag;
  uint8_t algorithm;
  uint8_t digest_type;
  size_t digest_len;
  uint8_t digest[64];
} hsk_ds_record_t;

typedef struct hsk_tls_record_s {
  uint8_t type;
  char protocol[256];
  uint16_t port;
  uint8_t usage;
  uint8_t selector;
  uint8_t matching_type;
  size_t certificate_len;
  uint8_t certificate[64];
} hsk_tls_record_t;

typedef struct hsk_smime_record_s {
  uint8_t type;
  uint8_t hash[28];
  uint8_t usage;
  uint8_t selector;
  uint8_t matching_type;
  size_t certificate_len;
  uint8_t certificate[64];
} hsk_smime_record_t;

typedef struct hsk_ssh_record_s {
  uint8_t type;
  uint8_t algorithm;
  uint8_t digest_type;
  size_t fingerprint_len;
  uint8_t fingerprint[64];
} hsk_ssh_record_t;

typedef struct hsk_pgp_record_s {
  uint8_t hash[28];
  size_t pubkey_len;
  uint8_t pubkey[512];
} hsk_pgp_record_t;

typedef struct hsk_addr_record_s {
  uint8_t type;
  char currency[256];
  char address[256];
  uint8_t ctype;
  bool testnet;
  uint8_t version;
  size_t hash_len;
  uint8_t hash[64];
} hsk_addr_record_t;

typedef struct hsk_extra_record_s {
  uint8_t type;
  uint8_t rtype;
  size_t data_len;
  uint8_t data[255];
} hsk_extra_record_t;

// Resource
typedef struct hsk_resource_s {
  uint8_t version;
  bool compat;
  uint32_t ttl;
  size_t record_count;
  hsk_record_t *records[255];
} hsk_resource_t;

void
hsk_resource_free(hsk_resource_t *res);

bool
hsk_resource_decode(
  const uint8_t *data,
  size_t data_len,
  hsk_resource_t **res
);

const hsk_record_t *
hsk_resource_get(const hsk_resource_t *res, uint8_t type);

bool
hsk_resource_has(const hsk_resource_t *res, uint8_t type);

hsk_dns_msg_t *
hsk_resource_to_dns(const hsk_resource_t *rs, const char *name, uint16_t type);

hsk_dns_msg_t *
hsk_resource_root(uint16_t type, const hsk_addr_t *addr);

hsk_dns_msg_t *
hsk_resource_to_nx(void);

hsk_dns_msg_t *
hsk_resource_to_servfail(void);

hsk_dns_msg_t *
hsk_resource_to_notimp(void);

bool
hsk_resource_is_ptr(const char *name);
#endif
