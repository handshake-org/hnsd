#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#include "chain.h"
#include "dns.h"
#include "ns.h"
#include "pool.h"
#include "req.h"

static bool
hsk_hesiod_txt_push(char *name, char *text, hsk_dns_rrs_t *an) {
  hsk_dns_rr_t *rr = hsk_dns_rr_create(HSK_DNS_TXT);

  if (!rr)
    return false;

  rr->ttl = 0;
  hsk_dns_rr_set_name(rr, name);
  hsk_dns_txt_rd_t *rd = rr->rd;
  hsk_dns_txt_t *txt = hsk_dns_txt_alloc();

  if (!txt) {
    hsk_dns_rr_free(rr);
    return false;
  }

  txt->data_len = strlen(text);
  strcpy((char *)&txt->data[0], text);

  hsk_dns_txts_push(&rd->txts, txt);
  hsk_dns_rrs_push(an, rr);
  return true;
}

static bool
hsk_hesiod_txt_push_int(char *name, uint64_t n, hsk_dns_rrs_t *an) {
  char height[16];
  sprintf(height, "%lld", n);
  return hsk_hesiod_txt_push(name, height,an);
}

static bool
hsk_hesiod_txt_push_hash(char *name, uint8_t *data, hsk_dns_rrs_t *an) {
  char hash[65];
  for (int i = 0; i < 32; i++)
    sprintf(&hash[i * 2], "%02x", data[i]);
  return hsk_hesiod_txt_push(name, hash, an);
}

static bool
hsk_hesiod_resolve_chain(
  char *name,
  hsk_chain_t *chain,
  hsk_dns_rrs_t *an
) {
  if (!hsk_hesiod_txt_push_int("height.tip.chain.hnsd.", chain->height, an))
    return false;

  if (!hsk_hesiod_txt_push_hash("hash.tip.chain.hnsd.", chain->tip->hash, an))
    return false;

  return true;
}

static bool
hsk_hesiod_resolve_pool(
  char *name,
  hsk_pool_t *pool,
  hsk_dns_rrs_t *an
) {
  return false;
}

hsk_dns_msg_t *
hsk_hesiod_resolve(hsk_dns_req_t *req, hsk_ns_t *ns) {
  if (strcmp(req->tld, "hnsd") != 0) {
    return NULL;
  }

  hsk_dns_msg_t *msg = hsk_dns_msg_alloc();

  if (!msg)
    return NULL;

  msg->flags |= HSK_DNS_AA;

  char module[HSK_DNS_MAX_LABEL + 1];
  hsk_dns_label_get(req->name, -2, module);

  hsk_dns_rrs_t *an = &msg->an;
  if (strcmp(module, "chain") == 0) {
    if (!hsk_hesiod_resolve_chain(req->name, &ns->pool->chain, an))
      goto fail;

  } else if (strcmp(module, "pool") == 0) {
    if (!hsk_hesiod_resolve_pool(req->name, ns->pool, an))
      goto fail;

  } else {
    goto fail;
  }

  return msg;

fail:
  hsk_dns_msg_free(msg);
  return NULL;
}
