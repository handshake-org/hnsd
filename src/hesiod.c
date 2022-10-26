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
hsk_hesiod_txt_push_u64(char *name, uint64_t n, hsk_dns_rrs_t *an) {
  char number[65];
  sprintf(number, "%llu", n);
  return hsk_hesiod_txt_push(name, number, an);
}

static bool
hsk_hesiod_txt_push_hash(char *name, uint8_t *data, hsk_dns_rrs_t *an) {
  char hash[65];
  for (int i = 0; i < 32; i++)
    sprintf(&hash[i * 2], "%02x", data[i]);
  return hsk_hesiod_txt_push(name, hash, an);
}

static bool
hsk_hesiod_txt_push_float(char *name, float f, hsk_dns_rrs_t *an) {
  char value[65];
  sprintf(value, "%f", f);
  return hsk_hesiod_txt_push(name, value, an);
}

static bool
hsk_hesiod_txt_push_peer(hsk_peer_t *peer, hsk_dns_rrs_t *an) {
  char label[65];
  char sublabel[40];
  sprintf(sublabel, "%llu.peers.pool.hnsd.", peer->id);

  sprintf(label, "host.%s", sublabel);
  if (!hsk_hesiod_txt_push(label, peer->host, an))
    return false;

  sprintf(label, "agent.%s", sublabel);
  if (!hsk_hesiod_txt_push(label, peer->agent, an))
    return false;

  return true;
}

hsk_dns_msg_t *
hsk_hesiod_resolve(hsk_dns_req_t *req, hsk_ns_t *ns) {
  hsk_dns_msg_t *msg = hsk_dns_msg_alloc();

  if (!msg)
    return NULL;

  msg->flags |= HSK_DNS_AA;
  hsk_dns_rrs_t *an = &msg->an;

  // CHAIN
  //   TIP
  if (hsk_dns_is_subdomain(req->name, "hash.tip.chain.hnsd.")) {
    if (!hsk_hesiod_txt_push_hash("hash.tip.chain.hnsd.",
                                  ns->pool->chain.tip->hash,
                                  an))
      goto fail;
  }

  if (hsk_dns_is_subdomain(req->name, "height.tip.chain.hnsd.")) {
    if (!hsk_hesiod_txt_push_u64("height.tip.chain.hnsd.",
                                 ns->pool->chain.tip->height,
                                 an))
      goto fail;
  }

  if (hsk_dns_is_subdomain(req->name, "time.tip.chain.hnsd.")) {
    if (!hsk_hesiod_txt_push_u64("time.tip.chain.hnsd.",
                                 ns->pool->chain.tip->time,
                                 an))
      goto fail;
  }

  if (hsk_dns_is_subdomain(req->name, "synced.tip.chain.hnsd.")) {
    if (!hsk_hesiod_txt_push("synced.tip.chain.hnsd.",
                             ns->pool->chain.synced ? "true" : "false",
                             an))
      goto fail;
  }

  //   PROGRESS
  if (hsk_dns_is_subdomain(req->name, "progress.chain.hnsd.")) {
    if (!hsk_hesiod_txt_push_float("progress.chain.hnsd.",
                             hsk_chain_progress(&ns->pool->chain),
                             an))
      goto fail;
  }

  // POOL
  //  SIZE
  if (hsk_dns_is_subdomain(req->name, "size.pool.hnsd.")) {
    char size[65];
    sprintf(size, "%d", ns->pool->size);
    if (!hsk_hesiod_txt_push("size.pool.hnsd.",
                             size,
                             an))
      goto fail;
  }

  //  PEERS
  if (hsk_dns_is_subdomain(req->name, "peers.pool.hnsd.")) {
    hsk_peer_t *peerIter, *next;
    for (peerIter = ns->pool->head; peerIter; peerIter = next) {
      if (!hsk_hesiod_txt_push_peer(peerIter, an))
        goto fail;

      next = peerIter->next;
    }
  }


  return msg;

fail:
  hsk_dns_msg_free(msg);
  return NULL;
}
