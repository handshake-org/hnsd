#ifndef _HSK_RESOURCE_H
#define _HSK_RESOURCE_H

#define HSK_DS 0
#define HSK_NS 1
#define HSK_GLUE4 2
#define HSK_GLUE6 3
#define HSK_SYNTH4 4
#define HSK_SYNTH6 5
#define HSK_TEXT 6

#define HSK_DEFAULT_TTL 21600

#include <stdint.h>
#include <stdbool.h>
#include "addr.h"
#include "dns.h"

// Dummy record placeholder
typedef struct hsk_record_s {
  uint8_t type;
  uint8_t name[HSK_DNS_MAX_NAME];
  uint8_t inet4[4];
  uint8_t inet6[16];
} hsk_record_t;

// Resoruce serialization version 0 record types
typedef struct hsk_ds_record_s {
  uint8_t type;
  uint16_t key_tag;
  uint8_t algorithm;
  uint8_t digest_type;
  size_t digest_len;
  uint8_t digest[64];
} hsk_ds_record_t;

typedef hsk_record_t hsk_ns_record_t;

typedef hsk_record_t hsk_glue4_record_t;

typedef hsk_record_t hsk_glue6_record_t;

typedef hsk_record_t hsk_synth4_record_t;

typedef hsk_record_t hsk_synth6_record_t;

typedef struct hsk_txt_record_s {
  uint8_t type;
  hsk_dns_txts_t txts;
} hsk_txt_record_t;

// Resource
typedef struct hsk_resource_s {
  uint8_t version;
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

bool
hsk_resource_has_ns(const hsk_resource_t *res);

hsk_dns_msg_t *
hsk_resource_to_dns(const hsk_resource_t *rs, const uint8_t *name, uint16_t type);

hsk_dns_msg_t *
hsk_resource_root(uint16_t type, const hsk_addr_t *addr);

hsk_dns_msg_t *
hsk_resource_to_nx(void);

hsk_dns_msg_t *
hsk_resource_to_servfail(void);

hsk_dns_msg_t *
hsk_resource_to_notimp(void);

bool
hsk_resource_is_ptr(const uint8_t *name);

bool
hsk_resource_to_empty(
  const uint8_t *name,
  const uint8_t *type_map,
  size_t type_map_len,
  hsk_dns_rrs_t *an
);

bool
hsk_resource_root_to_soa(hsk_dns_rrs_t *an);

void
ip_to_b32(const uint8_t *ip, char *dst, uint8_t family);

bool
b32_to_ip(const char *str, uint8_t *ip, uint16_t *family);

bool
pointer_to_ip(const uint8_t *name, uint8_t *ip, uint16_t *family);
#endif
