#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "bio.h"
#include "constants.h"
#include "error.h"
#include "hash.h"
#include "proof.h"

static bool
to_nibbles(uint8_t *data, size_t data_len, uint8_t *nib, size_t nib_len) {
  size_t l = data_len * 2 + 1;

  if (nib_len < l)
    return false;

  int32_t j = 0;
  int32_t i;

  for (i = 0; i < data_len; i++) {
    uint8_t b = data[i];
    nib[j++] = b >> 4;
    nib[j++] = b & 0x0f;
  }

  nib[j] = 16;

  return true;
}

static bool
decompress(uint8_t *data, size_t data_len, uint8_t **dec, size_t *dec_len) {
  if (data_len == 0) {
    *dec = NULL;
    *dec_len = 0;
    return true;
  }

  size_t nib_len = data_len * 2 + 1;
  uint8_t *nib = (uint8_t *)malloc(nib_len);

  if (nib == NULL)
    return false;

  if (!to_nibbles(data, data_len, nib, nib_len))
    return false;

  int32_t pos = 2;
  int32_t len = nib_len - 1;

  if (*nib & 1)
    pos = 1;

  if (*nib & 2)
    len += 1;

  int32_t i;
  for (i = pos; i < len; i++)
    nib[i - pos] = nib[i];

  *dec = nib;
  *dec_len = len - pos;

  return true;
}

void
hsk_node_init(uint8_t type, hsk_node_t *node) {
  switch (type) {
    case HSK_NULLNODE: {
      break;
    }
    case HSK_HASHNODE: {
      hsk_hashnode_t *n = (hsk_hashnode_t *)node;
      n->type = type;
      memset(n->data, 0, 32);
      break;
    }
    case HSK_SHORTNODE: {
      hsk_shortnode_t *n = (hsk_shortnode_t *)node;
      n->type = type;
      n->key = NULL;
      n->key_len = 0;
      n->value = NULL;
      break;
    }
    case HSK_FULLNODE: {
      hsk_fullnode_t *n = (hsk_fullnode_t *)node;
      n->type = type;

      int32_t i;
      for (i = 0; i < 17; i++)
        n->children[i] = NULL;

      break;
    }
    case HSK_VALUENODE: {
      hsk_valuenode_t *n = (hsk_valuenode_t *)node;
      n->type = type;
      n->data = NULL;
      n->data_len = 0;
      break;
    }
    default: {
      assert(false);
    }
  }
}

bool
hsk_node_alloc(uint8_t type, hsk_node_t **node) {
  *node = NULL;

  switch (type) {
    case HSK_NULLNODE: {
      *node = NULL;
      break;
    }
    case HSK_HASHNODE: {
      hsk_hashnode_t *n = malloc(sizeof(hsk_hashnode_t));
      if (n == NULL)
        return false;
      *node = (hsk_node_t *)n;
      break;
    }
    case HSK_SHORTNODE: {
      hsk_shortnode_t *n = malloc(sizeof(hsk_shortnode_t));
      if (n == NULL)
        return false;
      *node = (hsk_node_t *)n;
      break;
    }
    case HSK_FULLNODE: {
      hsk_fullnode_t *n = malloc(sizeof(hsk_fullnode_t));
      if (n == NULL)
        return false;
      *node = (hsk_node_t *)n;
      break;
    }
    case HSK_VALUENODE: {
      hsk_valuenode_t *n = malloc(sizeof(hsk_valuenode_t));
      if (n == NULL)
        return false;
      *node = (hsk_node_t *)n;
      break;
    }
    default: {
      return false;
    }
  }

  hsk_node_init(type, *node);

  return true;
}

void
hsk_free_node(hsk_node_t *node, bool recurse) {
  if (node == NULL)
    return;

  switch (node->type) {
    case HSK_NULLNODE: {
      break;
    }
    case HSK_HASHNODE: {
      hsk_hashnode_t *n = (hsk_hashnode_t *)node;
      free(n);
      break;
    }
    case HSK_SHORTNODE: {
      hsk_shortnode_t *n = (hsk_shortnode_t *)node;

      if (n->key)
        free(n->key);

      if (recurse)
        hsk_free_node(n->value, recurse);

      free(n);

      break;
    }
    case HSK_FULLNODE: {
      hsk_fullnode_t *n = (hsk_fullnode_t *)node;

      if (recurse) {
        int32_t i;
        for (i = 0; i < 17; i++)
          hsk_free_node(n->children[i], recurse);
      }

      free(n);

      break;
    }
    case HSK_VALUENODE: {
      hsk_valuenode_t *n = (hsk_valuenode_t *)node;

      if (n->data)
        free(n->data);

      free(n);

      break;
    }
    default: {
      assert(false);
    }
  }
}

bool
hsk_node_read(uint8_t **data, size_t *data_len, hsk_node_t **node) {
  uint8_t type;

  *node = NULL;

  if (!read_u8(data, data_len, &type))
    return false;

  if (!hsk_node_alloc(type, node))
    return false;

  switch (type) {
    case HSK_NULLNODE: {
      *node = NULL;
      return true;
    }
    case HSK_HASHNODE: {
      hsk_hashnode_t *n = (hsk_hashnode_t *)*node;

      if (!read_bytes(data, data_len, n->data, 32))
        goto fail;

      return true;
    }
    case HSK_SHORTNODE: {
      hsk_shortnode_t *n = (hsk_shortnode_t *)*node;

      uint8_t *out;
      size_t out_len;

      if (!slice_varbytes(data, data_len, &out, &out_len))
        goto fail;

      if (!decompress(out, out_len, &n->key, &n->key_len))
        goto fail;

      if (!hsk_node_read(data, data_len, &n->value))
        goto fail;

      return true;
    }
    case HSK_FULLNODE: {
      hsk_fullnode_t *n = (hsk_fullnode_t *)*node;

      int32_t i;
      for (i = 0; i < 17; i++) {
        if (!hsk_node_read(data, data_len, &n->children[i]))
          goto fail;
      }

      return true;
    }
    case HSK_VALUENODE: {
      hsk_valuenode_t *n = (hsk_valuenode_t *)*node;

      if (!alloc_varbytes(data, data_len, &n->data, &n->data_len))
        goto fail;

      return true;
    }
    default: {
      goto fail;
    }
  }

fail:
  hsk_free_node(*node, true);
  *node = NULL;
  return false;
}

bool
hsk_node_decode(uint8_t *data, size_t data_len, hsk_node_t **node) {
  return hsk_node_read(&data, &data_len, node);
}

static bool
starts_with(uint8_t *kk, size_t kl, uint8_t *nk, size_t nkl) {
  if (kl < nkl)
    return false;

  return memcmp(kk, nk, nkl) == 0;
}

static int32_t
next_child(hsk_node_t **node, uint8_t **kk, size_t *kl) {
  while (*kl > 0) {
    if (*node == NULL) {
      hsk_free_node(*node, true);
      *node = NULL;
      *kl = 0;
      return HSK_SUCCESS;
    }

    switch ((*node)->type) {
      case HSK_SHORTNODE: {
        hsk_shortnode_t *n = (hsk_shortnode_t *)*node;
        hsk_node_t *nn = n->value;

        if (!starts_with(*kk, *kl, n->key, n->key_len)) {
          hsk_free_node(*node, true);
          *node = NULL;
          *kl = 0;
          return HSK_SUCCESS;
        }

        *kk += n->key_len;
        *kl -= n->key_len;

        hsk_free_node(*node, false);
        *node = nn;

        break;
      }
      case HSK_FULLNODE: {
        hsk_fullnode_t *n = (hsk_fullnode_t *)*node;
        hsk_node_t *nn = n->children[**kk];

        int32_t j;
        for (j = 0; j < 17; j++) {
          if (j != **kk)
            hsk_free_node(n->children[j], true);
        }

        hsk_free_node(*node, false);

        *node = nn;
        *kk += 1;
        *kl -= 1;

        break;
      }
      case HSK_HASHNODE: {
        return HSK_SUCCESS;
      }
      case HSK_VALUENODE: {
        return HSK_EUNEXPECTEDNODE;
      }
      default: {
        return HSK_EINVALIDNODE;
      }
    }
  }

  if (*node == NULL)
    return HSK_SUCCESS;

  if ((*node)->type != HSK_VALUENODE) {
    hsk_free_node(*node, true);
    *node = NULL;
    return HSK_SUCCESS;
  }

  return HSK_SUCCESS;
}

int32_t
hsk_proof_verify(
  uint8_t *root,
  uint8_t *key,
  hsk_raw_node_t *nodes,
  bool *exists,
  uint8_t **data,
  size_t *data_len
) {
  if (root == NULL || key == NULL)
    return HSK_EBADARGS;

  // Nibble key & key length
  uint8_t k[65];
  uint8_t *kk = &k[0];
  size_t kl = 65;

  // Current hash and hash buffer.
  uint8_t expect[32];
  uint8_t hash[32];
  memcpy(&expect[0], root, 32);

  // Current node.
  hsk_node_t *node = NULL;

  // Return code.
  int32_t rc = 0;

  // Nibblify the key.
  assert(to_nibbles(key, 32, kk, 65));

  hsk_raw_node_t *c;

  for (c = nodes; c; c = c->next) {
    hsk_hash_blake2b(c->data, c->data_len, hash);

    if (memcmp(hash, expect, 32) != 0) {
      rc = HSK_EHASHMISMATCH;
      goto done;
    }

    node = NULL;

    if (!hsk_node_decode(c->data, c->data_len, &node)) {
      rc = HSK_EMALFORMEDNODE;
      goto done;
    }

    rc = next_child(&node, &kk, &kl);

    if (rc != HSK_SUCCESS)
      goto done;

    if (node == NULL) {
      if (c->next)
        return HSK_EEARLYEND;

      if (exists)
        *exists = false;

      if (data)
        *data = NULL;

      if (data_len)
        *data_len = 0;

      return HSK_EPROOFOK;
    }

    switch (node->type) {
      case HSK_HASHNODE: {
        memcpy(expect, ((hsk_hashnode_t *)node)->data, 32);
        hsk_free_node(node, true);
        node = NULL;
        break;
      }
      case HSK_VALUENODE: {
        if (c->next) {
          rc = HSK_EEARLYEND;
          goto done;
        }

        hsk_valuenode_t *n = (hsk_valuenode_t *)node;

        if (n->data_len > HSK_MAX_DATA_SIZE) {
          rc = HSK_EHASHMISMATCH;
          goto done;
        }

        if (exists)
          *exists = true;

        if (data)
          *data = n->data;

        if (data_len)
          *data_len = n->data_len;

        free(node);

        return HSK_EPROOFOK;
      }
      default: {
        rc = HSK_EINVALIDNODE;
        goto done;
      }
    }
  }

  rc = HSK_ENORESULT;
done:
  hsk_free_node(node, true);
  return rc;
}

void
hsk_raw_node_init(hsk_raw_node_t *n) {
  if (n == NULL)
    return;

  n->data = NULL;
  n->data_len = 0;
  n->next = NULL;
}

hsk_raw_node_t *
hsk_raw_node_alloc() {
  hsk_raw_node_t *n = malloc(sizeof(hsk_raw_node_t));
  hsk_raw_node_init(n);
  return n;
}

void
hsk_raw_node_free(hsk_raw_node_t *n) {
  if (n == NULL)
    return;

  if (n->data)
    free(n->data);

  free(n);
}

void
hsk_raw_node_free_list(hsk_raw_node_t *n) {
  hsk_raw_node_t *node, *next;
  for (node = n; node; node = next) {
    next = node->next;
    hsk_raw_node_free(node);
  }
}
