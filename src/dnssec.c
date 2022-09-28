#include "config.h"

#include <assert.h>

#include "dns.h"
#include "dnssec.h"

static hsk_dns_rr_t *ksk_key = NULL;
static hsk_dns_rr_t *zsk_key = NULL;
static hsk_dns_rr_t *ksk_ds = NULL;

const hsk_dns_rr_t *
hsk_dnssec_get_ksk(void) {
  if (ksk_key)
    return (const hsk_dns_rr_t *)ksk_key;

  const uint8_t *ksk = &hsk_dnssec_ksk[0];

  uint8_t root[HSK_DNS_MAX_NAME] = {0};
  ksk_key = hsk_dns_dnskey_create(root, ksk, true);
  assert(ksk_key);

  return (const hsk_dns_rr_t *)ksk_key;
}

const hsk_dns_rr_t *
hsk_dnssec_get_zsk(void) {
  if (zsk_key)
    return (const hsk_dns_rr_t *)zsk_key;

  const uint8_t *zsk = &hsk_dnssec_zsk[0];

  uint8_t root[HSK_DNS_MAX_NAME] = {0};
  zsk_key = hsk_dns_dnskey_create(root, zsk, false);
  assert(zsk_key);

  return (const hsk_dns_rr_t *)zsk_key;
}

const hsk_dns_rr_t *
hsk_dnssec_get_ds(void) {
  if (ksk_ds)
    return (const hsk_dns_rr_t *)ksk_ds;

  ksk_ds = hsk_dns_ds_create(hsk_dnssec_get_ksk());
  assert(ksk_ds);

  return (const hsk_dns_rr_t *)ksk_ds;
}

bool
hsk_dnssec_sign_ksk(hsk_dns_rrs_t *rrs, uint16_t type) {
  const uint8_t *priv = &hsk_dnssec_ksk[0];
  const hsk_dns_rr_t *key = hsk_dnssec_get_ksk();

  return hsk_dns_sign_type(rrs, type, key, priv);
}

bool
hsk_dnssec_sign_zsk(hsk_dns_rrs_t *rrs, uint16_t type) {
  const uint8_t *priv = &hsk_dnssec_zsk[0];
  const hsk_dns_rr_t *key = hsk_dnssec_get_zsk();

  return hsk_dns_sign_type(rrs, type, key, priv);
}
