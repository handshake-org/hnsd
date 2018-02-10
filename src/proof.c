#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>
#include <stdbool.h>

#include "hash.h"
#include "bio.h"
#include "hsk-error.h"
#include "hsk-proof.h"

static int32_t
to_nibbles(uint8_t *data, size_t data_len, uint8_t **nib, size_t *nib_len) {
  if (data == NULL || nib == NULL)
    return HSK_EBADARGS;

  size_t l = data_len * 2 + 1;

  *nib = (uint8_t *)malloc(l);
  *nib_len = 0;

  if (nib == NULL)
    return HSK_ENOMEM;

  int32_t j = 0;
  int32_t i;

  for (i = 0; i < data_len; i++) {
    uint8_t b = data[i];
    (*nib)[j++] = b >> 4;
    (*nib)[j++] = b & 0x0f;
  }

  (*nib)[j] = 16;
  *nib_len = l;

  return HSK_SUCCESS;
}

static int32_t
decompress(uint8_t *data, size_t data_len, uint8_t **dec, size_t *dec_len) {
  if (data == NULL || dec == NULL)
    return HSK_EBADARGS;

  if (data_len == 0) {
    *dec = malloc(0);
    *dec_len = 0;
    return HSK_SUCCESS;
  }

  uint8_t *nib;
  size_t nib_len;
  int32_t rc = to_nibbles(data, data_len, &nib, &nib_len);

  if (rc != HSK_SUCCESS)
    return rc;

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

  return HSK_SUCCESS;
}

static int32_t
next_child(hsk_node_t **node, uint8_t *k, int32_t *p) {
  while (65 - *p > 0) {
    if (*node == NULL) {
      hsk_free_node(*node, true);
      *node = NULL;
      *p = -1;
      return HSK_SUCCESS;
    }

    switch ((*node)->type) {
      case HSK_SHORTNODE: {
        hsk_shortnode_t *n = (hsk_shortnode_t *)*node;
        if (65 - *p < n->key_len || memcmp(k + *p, n->key, n->key_len) != 0) {
          hsk_free_node(*node, true);
          *node = NULL;
          *p = -1;
          return HSK_SUCCESS;
        }
        *p += n->key_len;
        hsk_node_t *nn = n->value;
        hsk_free_node(*node, false);
        *node = nn;
        break;
      }
      case HSK_FULLNODE: {
        hsk_fullnode_t *n = (hsk_fullnode_t *)*node;
        hsk_node_t *nn = n->children[k[*p]];
        int32_t j;
        for (j = 0; j < 17; j++) {
          if (j != k[*p])
            hsk_free_node(n->children[j], true);
        }
        hsk_free_node(*node, false);
        *node = nn;
        *p += 1;
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

  if (*node == NULL || (*node)->type != HSK_VALUENODE) {
    hsk_free_node(*node, true);
    *node = NULL;
    *p = -1;
    return HSK_SUCCESS;
  }

  *p = -1;
  return HSK_SUCCESS;
}

int32_t
hsk_parse_node(
  uint8_t *data,
  size_t data_len,
  hsk_node_t **node,
  uint8_t **ret_data,
  size_t *ret_len
) {
  if (data_len < 1)
    return HSK_EMALFORMEDNODE;

  uint8_t type = *data;
  data += 1;
  data_len -= 1;

  switch (type) {
    case HSK_NULLNODE: {
      *node = NULL;
      goto success;
    }
    case HSK_HASHNODE: {
      if (data_len < 32)
        return HSK_EMALFORMEDNODE;

      hsk_hashnode_t *n = malloc(sizeof(hsk_hashnode_t));

      if (n == NULL)
        return HSK_ENOMEM;

      n->type = type;

      memcpy(n->data, data, 32);

      data += 32;
      data_len -= 32;

      *node = (hsk_node_t *)n;

      goto success;
    }
    case HSK_SHORTNODE: {
      hsk_shortnode_t *n = malloc(sizeof(hsk_shortnode_t));

      if (n == NULL)
        return HSK_ENOMEM;

      n->type = type;

      int32_t rc;

      uint8_t *out;
      size_t out_len;

      if (!slice_varbytes(&data, &data_len, &out, &out_len)) {
        free(n);
        return HSK_EENCODING;
      }

      uint8_t *dec;
      size_t dec_len;

      rc = decompress(out, out_len, &dec, &dec_len);

      if (rc != HSK_SUCCESS) {
        free(n);
        return rc;
      }

      n->key = dec;
      n->key_len = dec_len;
      n->value = NULL;

      rc = hsk_parse_node(data, data_len, &n->value, &data, &data_len);

      if (rc != HSK_SUCCESS) {
        free(dec);
        free(n);
        return rc;
      }

      *node = (hsk_node_t *)n;

      goto success;
    }
    case HSK_FULLNODE: {
      hsk_fullnode_t *n = malloc(sizeof(hsk_fullnode_t));

      if (n == NULL)
        return HSK_ENOMEM;

      n->type = type;

      int32_t i;
      for (i = 0; i < 17; i++) {
        n->children[i] = NULL;
        int32_t rc = hsk_parse_node(data, data_len, &n->children[i], &data, &data_len);
        if (rc != HSK_SUCCESS) {
          while (i--)
            hsk_free_node(n->children[i], true);
          free(n);
          return rc;
        }
      }

      *node = (hsk_node_t *)n;

      goto success;
    }
    case HSK_VALUENODE: {
      hsk_valuenode_t *n = malloc(sizeof(hsk_valuenode_t));

      if (n == NULL)
        return HSK_ENOMEM;

      n->type = type;

      uint8_t *out;
      size_t out_len;

      if (!alloc_varbytes(&data, &data_len, &out, &out_len)) {
        free(n);
        return HSK_EENCODING;
      }

      n->data = out;
      n->data_len = out_len;

      *node = (hsk_node_t *)n;

      goto success;
    }
    default: {
      return HSK_EMALFORMEDNODE;
    }
  }

success:
  if (ret_data)
    *ret_data = data;

  if (ret_len)
    *ret_len = data_len;

  return HSK_SUCCESS;
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
      free(n->data);
      free(n);
      break;
    }
    default: {
      assert(false);
    }
  }
}

int32_t
hsk_verify_proof(
  uint8_t *root,
  uint8_t *key,
  hsk_raw_node_t *nodes,
  uint8_t **data,
  size_t *data_len
) {
  if (data == NULL || data_len == NULL)
    return HSK_EBADARGS;

  *data = NULL;
  *data_len = 0;

  if (root == NULL || key == NULL)
    return HSK_EBADARGS;

  uint8_t *k;
  size_t kl;

  if (to_nibbles(key, 32, &k, &kl) != 0)
    return HSK_ENOMEM;

  assert(kl == 65);

  hsk_raw_node_t *c;
  uint8_t *h = root;
  uint8_t hash[32];
  hsk_node_t *node = NULL;
  hsk_node_t *last_hn = NULL;
  int32_t p = 0;

  for (c = nodes; c; c = c->next) {
    hsk_blake2b(c->data, c->len, hash);

    if (memcmp(hash, h, 32) != 0) {
      free(k);
      hsk_free_node(last_hn, true);
      return HSK_EHASHMISMATCH;
    }

    hsk_free_node(last_hn, true);
    last_hn = NULL;

    int32_t rc;

    rc = hsk_parse_node(c->data, c->len, &node, NULL, NULL);

    if (rc != HSK_SUCCESS) {
      free(k);
      return rc;
    }

    rc = next_child(&node, k, &p);

    if (rc != HSK_SUCCESS) {
      free(k);
      hsk_free_node(node, true);
      return rc;
    }

    if (node == NULL) {
      free(k);
      if (c->next)
        return HSK_EEARLYEND;
      return HSK_EPROOFOK;
    }

    switch (node->type) {
      case HSK_HASHNODE: {
        h = ((hsk_hashnode_t *)node)->data;
        last_hn = node;
        break;
      }
      case HSK_VALUENODE: {
        if (c->next)
          return HSK_EEARLYEND;
        hsk_valuenode_t *n = (hsk_valuenode_t *)node;
        *data = n->data;
        *data_len = n->data_len;
        free(k);
        free(node);
        return HSK_EPROOFOK;
      }
      default: {
        free(k);
        hsk_free_node(node, true);
        return HSK_EINVALIDNODE;
      }
    }
  }

  free(k);
  hsk_free_node(last_hn, true);
  return HSK_ENORESULT;
}

int32_t
hsk_verify_name(
  uint8_t *root,
  char *name,
  hsk_raw_node_t *nodes,
  uint8_t **data,
  size_t *data_len
) {
  uint8_t key[32];
  hsk_blake2b(name, strlen(name), key);
  return hsk_verify_proof(root, key, nodes, data, data_len);
}
