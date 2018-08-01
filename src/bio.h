#ifndef _HSK_BIO_H
#define _HSK_BIO_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static inline bool
read_u8(uint8_t **data, size_t *len, uint8_t *out) {
  if (*len < 1)
    return false;
  *out = (*data)[0];
  *data += 1;
  *len -= 1;
  return true;
}

static inline bool
read_u16(uint8_t **data, size_t *len, uint16_t *out) {
  if (*len < 2)
    return false;
#ifndef HSK_BIG_ENDIAN
  memcpy(out, *data, 2);
#else
  *out = 0;
  *out |= ((uint16_t)(*data)[1]) << 8;
  *out |= (uint16_t)(*data)[0];
#endif
  *data += 2;
  *len -= 2;
  return true;
}

static inline bool
read_u32(uint8_t **data, size_t *len, uint32_t *out) {
  if (*len < 4)
    return false;
#ifndef HSK_BIG_ENDIAN
  memcpy(out, *data, 4);
#else
  *out = 0;
  *out |= ((uint32_t)(*data)[3]) << 24;
  *out |= ((uint32_t)(*data)[2]) << 16;
  *out |= ((uint32_t)(*data)[1]) << 8;
  *out |= (uint32_t)(*data)[0];
#endif
  *data += 4;
  *len -= 4;
  return true;
}

static inline bool
read_u64(uint8_t **data, size_t *len, uint64_t *out) {
  if (*len < 8)
    return false;
#ifndef HSK_BIG_ENDIAN
  memcpy(out, *data, 8);
#else
  *out = 0;
  *out |= ((uint64_t)(*data)[7]) << 56;
  *out |= ((uint64_t)(*data)[6]) << 48;
  *out |= ((uint64_t)(*data)[5]) << 40;
  *out |= ((uint64_t)(*data)[4]) << 32;
  *out |= ((uint64_t)(*data)[3]) << 24;
  *out |= ((uint64_t)(*data)[2]) << 16;
  *out |= ((uint64_t)(*data)[1]) << 8;
  *out |= (uint64_t)(*data)[0];
#endif
  *data += 8;
  *len -= 8;
  return true;
}

static inline bool
read_i8(uint8_t **data, size_t *len, int8_t *out) {
  return read_u8(data, len, (uint8_t *)out);
}

static inline bool
read_i16(uint8_t **data, size_t *len, int16_t *out) {
  return read_u16(data, len, (uint16_t *)out);
}

static inline bool
read_i32(uint8_t **data, size_t *len, int32_t *out) {
  return read_u32(data, len, (uint32_t *)out);
}

static inline bool
read_i64(uint8_t **data, size_t *len, int64_t *out) {
  return read_u64(data, len, (uint64_t *)out);
}

static inline bool
read_u16be(uint8_t **data, size_t *len, uint16_t *out) {
  if (*len < 2)
    return false;
#ifdef HSK_BIG_ENDIAN
  memcpy(out, *data, 2);
#else
  *out = 0;
  *out |= ((uint16_t)(*data)[0]) << 8;
  *out |= (uint16_t)(*data)[1];
#endif
  *data += 2;
  *len -= 2;
  return true;
}

static inline bool
read_u32be(uint8_t **data, size_t *len, uint32_t *out) {
  if (*len < 4)
    return false;
#ifdef HSK_BIG_ENDIAN
  memcpy(out, *data, 4);
#else
  *out = 0;
  *out |= ((uint32_t)(*data)[0]) << 24;
  *out |= ((uint32_t)(*data)[1]) << 16;
  *out |= ((uint32_t)(*data)[2]) << 8;
  *out |= (uint32_t)(*data)[3];
#endif
  *data += 4;
  *len -= 4;
  return true;
}

static inline bool
read_u64be(uint8_t **data, size_t *len, uint64_t *out) {
  if (*len < 8)
    return false;
#ifdef HSK_BIG_ENDIAN
  memcpy(out, *data, 8);
#else
  *out = 0;
  *out |= ((uint64_t)(*data)[0]) << 56;
  *out |= ((uint64_t)(*data)[1]) << 48;
  *out |= ((uint64_t)(*data)[2]) << 40;
  *out |= ((uint64_t)(*data)[3]) << 32;
  *out |= ((uint64_t)(*data)[4]) << 24;
  *out |= ((uint64_t)(*data)[5]) << 16;
  *out |= ((uint64_t)(*data)[6]) << 8;
  *out |= (uint64_t)(*data)[7];
#endif
  *data += 8;
  *len -= 8;
  return true;
}

static inline bool
read_i16be(uint8_t **data, size_t *len, int16_t *out) {
  return read_u16be(data, len, (uint16_t *)out);
}

static inline bool
read_i32be(uint8_t **data, size_t *len, int32_t *out) {
  return read_u32be(data, len, (uint32_t *)out);
}

static inline bool
read_i64be(uint8_t **data, size_t *len, int64_t *out) {
  return read_u64be(data, len, (uint64_t *)out);
}

static inline bool
slice_bytes(uint8_t **data, size_t *len, uint8_t **out, size_t size) {
  if (*len < size)
    return false;
  *out = *data;
  *data += size;
  *len -= size;
  return true;
}

static inline bool
read_bytes(uint8_t **data, size_t *len, uint8_t *out, size_t size) {
  if (*len < size)
    return false;
  memcpy(out, *data, size);
  *data += size;
  *len -= size;
  return true;
}

static inline bool
alloc_bytes(uint8_t **data, size_t *len, uint8_t **out, size_t size) {
  if (*len < size)
    return false;

  uint8_t *o = malloc(size);

  if (o == NULL)
    return false;

  if (!read_bytes(data, len, o, size)) {
    free(o);
    return false;
  }

  *out = o;

  return true;
}

static inline bool
slice_ascii(uint8_t **data, size_t *len, char **out, size_t size) {
  if (!slice_bytes(data, len, (uint8_t **)out, size))
    return false;

  uint8_t i;
  for (i = 0; i < size; i++) {
    uint8_t ch = (*out)[i];

    // No unicode.
    if (ch & 0x80)
      return false;

    // No DEL.
    if (ch == 0x7f)
      return false;

    // Any non-printable character can screw.
    // Tab, line feed, and carriage return all valid.
    if (ch < 0x20
        && ch != 0x09
        && ch != 0x0a
        && ch != 0x0d) {
      return false;
    }
  }

  return true;
}

static inline bool
read_ascii(uint8_t **data, size_t *len, char *out, size_t size) {
  char *chunk;

  if (!slice_ascii(data, len, &chunk, size))
    return false;

  memcpy((void *)out, chunk, size);
  out[size] = '\0';

  return true;
}

static inline bool
alloc_ascii(uint8_t **data, size_t *len, char **out, size_t size) {
  if (*len < size)
    return false;

  char *o = malloc(size + 1);

  if (o == NULL)
    return false;

  if (!read_ascii(data, len, o, size)) {
    free(o);
    return false;
  }

  *out = o;

  return true;
}

static inline size_t
write_u8(uint8_t **data, uint8_t out) {
  if (data == NULL || *data == NULL)
    return 1;
  (*data)[0] = out;
  *data += 1;
  return 1;
}

static inline size_t
write_u16(uint8_t **data, uint16_t out) {
  if (data == NULL || *data == NULL)
    return 2;
#ifndef HSK_BIG_ENDIAN
  memcpy(*data, &out, 2);
#else
  (*data)[0] = (uint8_t)out;
  (*data)[1] = (uint8_t)(out >> 8);
#endif
  *data += 2;
  return 2;
}

static inline size_t
write_u32(uint8_t **data, uint32_t out) {
  if (data == NULL || *data == NULL)
    return 4;
#ifndef HSK_BIG_ENDIAN
  memcpy(*data, &out, 4);
#else
  (*data)[0] = (uint8_t)out;
  (*data)[1] = (uint8_t)(out >> 8);
  (*data)[2] = (uint8_t)(out >> 16);
  (*data)[3] = (uint8_t)(out >> 24);
#endif
  *data += 4;
  return 4;
}

static inline size_t
write_u64(uint8_t **data, uint64_t out) {
  if (data == NULL || *data == NULL)
    return 8;
#ifndef HSK_BIG_ENDIAN
  memcpy(*data, &out, 8);
#else
  (*data)[0] = (uint8_t)out;
  (*data)[1] = (uint8_t)(out >> 8);
  (*data)[2] = (uint8_t)(out >> 16);
  (*data)[3] = (uint8_t)(out >> 24);
  (*data)[4] = (uint8_t)(out >> 32);
  (*data)[5] = (uint8_t)(out >> 40);
  (*data)[6] = (uint8_t)(out >> 48);
  (*data)[7] = (uint8_t)(out >> 56);
#endif
  *data += 8;
  return 8;
}

static inline size_t
write_i8(uint8_t **data, int8_t out) {
  return write_u8(data, (uint8_t)out);
}

static inline size_t
write_i16(uint8_t **data, int16_t out) {
  return write_u16(data, (uint16_t)out);
}

static inline size_t
write_i32(uint8_t **data, int32_t out) {
  return write_u32(data, (uint32_t)out);
}

static inline size_t
write_i64(uint8_t **data, int64_t out) {
  return write_u64(data, (uint64_t)out);
}

static inline size_t
write_u16be(uint8_t **data, uint16_t out) {
  if (data == NULL || *data == NULL)
    return 2;
#ifdef HSK_BIG_ENDIAN
  memcpy(*data, &out, 2);
#else
  (*data)[1] = (uint8_t)out;
  (*data)[0] = (uint8_t)(out >> 8);
#endif
  *data += 2;
  return 2;
}

static inline size_t
write_u32be(uint8_t **data, uint32_t out) {
  if (data == NULL || *data == NULL)
    return 4;
#ifdef HSK_BIG_ENDIAN
  memcpy(*data, &out, 4);
#else
  (*data)[3] = (uint8_t)out;
  (*data)[2] = (uint8_t)(out >> 8);
  (*data)[1] = (uint8_t)(out >> 16);
  (*data)[0] = (uint8_t)(out >> 24);
#endif
  *data += 4;
  return 4;
}

static inline size_t
write_u64be(uint8_t **data, uint64_t out) {
  if (data == NULL || *data == NULL)
    return 8;
#ifdef HSK_BIG_ENDIAN
  memcpy(*data, &out, 8);
#else
  (*data)[7] = (uint8_t)out;
  (*data)[6] = (uint8_t)(out >> 8);
  (*data)[5] = (uint8_t)(out >> 16);
  (*data)[4] = (uint8_t)(out >> 24);
  (*data)[3] = (uint8_t)(out >> 32);
  (*data)[2] = (uint8_t)(out >> 40);
  (*data)[1] = (uint8_t)(out >> 48);
  (*data)[0] = (uint8_t)(out >> 56);
#endif
  *data += 8;
  return 8;
}

static inline size_t
write_i16be(uint8_t **data, int16_t out) {
  return write_u16be(data, (uint16_t)out);
}

static inline size_t
write_i32be(uint8_t **data, int32_t out) {
  return write_u32be(data, (uint32_t)out);
}

static inline size_t
write_i64be(uint8_t **data, int64_t out) {
  return write_u64be(data, (uint64_t)out);
}

static inline size_t
write_bytes(uint8_t **data, const uint8_t *bytes, size_t size) {
  if (data == NULL || *data == NULL)
    return size;
  memcpy(*data, bytes, size);
  *data += size;
  return size;
}

static inline bool
read_varint(uint8_t **data, size_t *data_len, uint64_t *value) {
  if (data_len == 0)
    return false;

  uint8_t prefix = (*data)[0];

  *data += 1;
  *data_len -= 1;

  switch (prefix) {
    case 0xff: {
      uint64_t v;

      if (!read_u64(data, data_len, &v))
        return false;

      if (v <= 0xffffffff)
        return false;

      *value = v;
      return true;
    }
    case 0xfe: {
      uint32_t v;

      if (!read_u32(data, data_len, &v))
        return false;

      if (v <= 0xffff)
        return false;

      *value = (uint64_t)v;
      break;
    }
    case 0xfd: {
      uint16_t v;

      if (!read_u16(data, data_len, &v))
        return false;

      if (v < 0xfd)
        return false;

      *value = (uint64_t)v;
      break;
    }
    default: {
      *value = (uint64_t)prefix;
      break;
    }
  }

  return true;
}

static inline bool
read_varsize(uint8_t **data, size_t *data_len, size_t *value) {
  size_t v;

  if (!read_varint(data, data_len, (uint64_t *)&v))
    return false;

  if ((int32_t)v < 0)
    return false;

  *value = v;

  return true;
}

static inline bool
size_varint(uint64_t value) {
  if (value < 0xfd)
    return 1;

  if (value <= 0xffff)
    return 3;

  if (value <= 0xffffffff)
    return 5;

  return 9;
}

static inline size_t
size_varsize(size_t value) {
  return size_varint((uint64_t)value);
}

static inline size_t
write_varint(uint8_t **data, uint64_t size) {
  if (data == NULL || *data == NULL)
    return size_varsize(size);

  if (size < 0xfd) {
    write_u8(data, (uint8_t)size);
    return 1;
  }

  if (size <= 0xffff) {
    write_u8(data, 0xfd);
    write_u16(data, (uint16_t)size);
    return 3;
  }

  if (size <= 0xffffffff) {
    write_u8(data, 0xfe);
    write_u32(data, (uint32_t)size);
    return 5;
  }

  write_u8(data, 0xff);
  write_u64(data, (uint64_t)size);
  return 9;
}

static inline size_t
write_varsize(uint8_t **data, size_t size) {
  return write_varint(data, (uint64_t)size);
}

static inline bool
slice_varbytes(
  uint8_t **data,
  size_t *data_len,
  uint8_t **out,
  size_t *out_len
) {
  size_t size;

  if (!read_varsize(data, data_len, &size))
    return false;

  if (!slice_bytes(data, data_len, out, size))
    return false;

  *out_len = size;

  return true;
}

static inline bool
read_varbytes(
  uint8_t **data,
  size_t *data_len,
  uint8_t *out,
  size_t out_size,
  size_t *out_len
) {
  size_t size;

  if (!read_varsize(data, data_len, &size))
    return false;

  if (out_size < size)
    return false;

  if (!read_bytes(data, data_len, out, size))
    return false;

  *out_len = size;

  return true;
}

static inline bool
alloc_varbytes(
  uint8_t **data,
  size_t *data_len,
  uint8_t **out,
  size_t *out_len
) {
  size_t size;

  if (!read_varsize(data, data_len, &size))
    return false;

  if (!alloc_bytes(data, data_len, out, size))
    return false;

  *out_len = size;

  return true;
}

static inline size_t
size_varbytes(size_t size) {
  return size_varsize(size) + size;
}

static inline size_t
write_varbytes(uint8_t **data, const uint8_t *bytes, size_t size) {
  if (data == NULL || *data == NULL)
    return size_varbytes(size);
  size_t s = 0;
  s += write_varsize(data, size);
  s += write_bytes(data, bytes, size);
  return s;
}

static inline uint8_t
get_u8(const uint8_t *data) {
  return data[0];
}

static inline uint16_t
get_u16(const uint8_t *data) {
  uint16_t out;
#ifndef HSK_BIG_ENDIAN
  memcpy(&out, data, 2);
#else
  out = 0;
  out |= ((uint16_t)data[1]) << 8;
  out |= (uint16_t)data[0];
#endif
  return out;
}

static inline uint32_t
get_u32(const uint8_t *data) {
  uint32_t out;
#ifndef HSK_BIG_ENDIAN
  memcpy(&out, data, 4);
#else
  out = 0;
  out |= ((uint32_t)data[3]) << 24;
  out |= ((uint32_t)data[2]) << 16;
  out |= ((uint32_t)data[1]) << 8;
  out |= (uint32_t)data[0];
#endif
  return out;
}

static inline uint64_t
get_u64(const uint8_t *data) {
  uint64_t out;
#ifndef HSK_BIG_ENDIAN
  memcpy(&out, data, 8);
#else
  out = 0;
  out |= ((uint64_t)data[7]) << 56;
  out |= ((uint64_t)data[6]) << 48;
  out |= ((uint64_t)data[5]) << 40;
  out |= ((uint64_t)data[4]) << 32;
  out |= ((uint64_t)data[3]) << 24;
  out |= ((uint64_t)data[2]) << 16;
  out |= ((uint64_t)data[1]) << 8;
  out |= (uint64_t)data[0];
#endif
  return out;
}

static inline int8_t
get_i8(const uint8_t *data) {
  return get_u8(data);
}

static inline int16_t
get_i16(const uint8_t *data) {
  return get_u16(data);
}

static inline int32_t
get_i32(const uint8_t *data) {
  return get_u32(data);
}

static inline int64_t
get_i64(const uint8_t *data) {
  return get_u64(data);
}

static inline uint16_t
get_u16be(const uint8_t *data) {
  uint16_t out;
#ifdef HSK_BIG_ENDIAN
  memcpy(&out, data, 2);
#else
  out = 0;
  out |= ((uint16_t)data[0]) << 8;
  out |= (uint16_t)data[1];
#endif
  return out;
}

static inline uint32_t
get_u32be(const uint8_t *data) {
  uint32_t out;
#ifdef HSK_BIG_ENDIAN
  memcpy(&out, data, 4);
#else
  out = 0;
  out |= ((uint32_t)data[0]) << 24;
  out |= ((uint32_t)data[1]) << 16;
  out |= ((uint32_t)data[2]) << 8;
  out |= (uint32_t)data[3];
#endif
  return out;
}

static inline uint64_t
get_u64be(const uint8_t *data) {
  uint64_t out;
#ifdef HSK_BIG_ENDIAN
  memcpy(&out, data, 8);
#else
  out = 0;
  out |= ((uint64_t)data[0]) << 56;
  out |= ((uint64_t)data[1]) << 48;
  out |= ((uint64_t)data[2]) << 40;
  out |= ((uint64_t)data[3]) << 32;
  out |= ((uint64_t)data[4]) << 24;
  out |= ((uint64_t)data[5]) << 16;
  out |= ((uint64_t)data[6]) << 8;
  out |= (uint64_t)data[7];
#endif
  return out;
}

static inline int16_t
get_i16be(const uint8_t *data) {
  return get_u16be(data);
}

static inline int32_t
get_i32be(const uint8_t *data) {
  return get_u32be(data);
}

static inline int64_t
get_i64be(const uint8_t *data) {
  return get_u64be(data);
}

static inline void
set_u8(uint8_t *data, uint8_t out) {
  data[0] = out;
}

static inline void
set_u16(uint8_t *data, uint16_t out) {
#ifndef HSK_BIG_ENDIAN
  memcpy(data, &out, 2);
#else
  data[0] = (uint8_t)out;
  data[1] = (uint8_t)(out >> 8);
#endif
}

static inline void
set_u32(uint8_t *data, uint32_t out) {
#ifndef HSK_BIG_ENDIAN
  memcpy(data, &out, 4);
#else
  data[0] = (uint8_t)out;
  data[1] = (uint8_t)(out >> 8);
  data[2] = (uint8_t)(out >> 16);
  data[3] = (uint8_t)(out >> 24);
#endif
}

static inline void
set_u64(uint8_t *data, uint64_t out) {
#ifndef HSK_BIG_ENDIAN
  memcpy(data, &out, 8);
#else
  data[0] = (uint8_t)out;
  data[1] = (uint8_t)(out >> 8);
  data[2] = (uint8_t)(out >> 16);
  data[3] = (uint8_t)(out >> 24);
  data[4] = (uint8_t)(out >> 32);
  data[5] = (uint8_t)(out >> 40);
  data[6] = (uint8_t)(out >> 48);
  data[7] = (uint8_t)(out >> 56);
#endif
}

static inline void
set_i8(uint8_t *data, int8_t out) {
  set_u8(data, (uint8_t)out);
}

static inline void
set_i16(uint8_t *data, int16_t out) {
  set_u16(data, (uint16_t)out);
}

static inline void
set_i32(uint8_t *data, int32_t out) {
  set_u32(data, (uint32_t)out);
}

static inline void
set_i64(uint8_t *data, int64_t out) {
  set_u64(data, (uint64_t)out);
}

static inline void
set_u16be(uint8_t *data, uint16_t out) {
#ifdef HSK_BIG_ENDIAN
  memcpy(data, &out, 2);
#else
  data[1] = (uint8_t)out;
  data[0] = (uint8_t)(out >> 8);
#endif
}

static inline void
set_u32be(uint8_t *data, uint32_t out) {
#ifdef HSK_BIG_ENDIAN
  memcpy(data, &out, 4);
#else
  data[3] = (uint8_t)out;
  data[2] = (uint8_t)(out >> 8);
  data[1] = (uint8_t)(out >> 16);
  data[0] = (uint8_t)(out >> 24);
#endif
}

static inline void
set_u64be(uint8_t *data, uint64_t out) {
#ifdef HSK_BIG_ENDIAN
  memcpy(data, &out, 8);
#else
  data[7] = (uint8_t)out;
  data[6] = (uint8_t)(out >> 8);
  data[5] = (uint8_t)(out >> 16);
  data[4] = (uint8_t)(out >> 24);
  data[3] = (uint8_t)(out >> 32);
  data[2] = (uint8_t)(out >> 40);
  data[1] = (uint8_t)(out >> 48);
  data[0] = (uint8_t)(out >> 56);
#endif
}

static inline void
set_i16be(uint8_t *data, int16_t out) {
  set_u16be(data, (uint16_t)out);
}

static inline void
set_i32be(uint8_t *data, int32_t out) {
  set_u32be(data, (uint32_t)out);
}

static inline void
set_i64be(uint8_t *data, int64_t out) {
  set_u64be(data, (uint64_t)out);
}
#endif
