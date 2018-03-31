/**
 * Parts of this software are based on Picnic:
 * https://github.com/IAIK/Picnic
 *
 *   Copyright (c) 2016-2017 Graz University of Technology
 *   Copyright (c) 2017 Angela Promitzer
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a
 *   copy of this software and associated documentation files (the
 *   ""Software""), to deal in the Software without restriction, including
 *   without limitation the rights to use, copy, modify, merge, publish,
 *   distribute, sublicense, and/or sell copies of the Software, and to permit
 *   persons to whom the Software is furnished to do so, subject to the
 *   following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *   DEALINGS IN THE SOFTWARE.
 */

#include "config.h"

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "random.h"

#if defined(__linux__) \
  && ((defined(HAVE_SYS_RANDOM_H) && defined(HAVE_GETRANDOM)) \
  || (__GLIBC__ > 2 || __GLIBC_MINOR__ >= 25))

#include <sys/random.h>

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  const ssize_t ret = getrandom(dst, len, GRND_NONBLOCK);
  if (ret < 0 || (size_t)ret != len)
    return false;
  return true;
}

#elif defined(__APPLE__) && defined(HAVE_APPLE_FRAMEWORK)

#include <Security/Security.h>

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  if (SecRandomCopyBytes(kSecRandomDefault, len, dst) == errSecSuccess)
    return true;
  return false;
}

#elif defined(__linux__) || defined(__APPLE__)

#include <stdio.h>

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  FILE *urandom = fopen("/dev/urandom", "r");

  if (!urandom)
    return false;

  size_t nbytes = fread(dst, 1, len, urandom);

  fclose(urandom);

  return nbytes == len;
}

#elif defined(_WIN16) || defined(_WIN32) || defined(_WIN64)

#if defined(HAVE_WINCRYPT_H)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  HCRYPTPROV prov;

  BOOL r = CryptAcquireContext(
    &prov,
    NULL,
    NULL,
    PROV_RSA_FULL,
    CRYPT_VERIFYCONTEXT
  );

  if (!r)
    return false;

  CryptGenRandom(prov, len, (BYTE *)dst);
  CryptReleaseContext(prov, 0);

  return true;
}
#else
#include <windows.h>

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  NTSTATUS r = BCryptGenRandom(NULL, dst, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

  if (!BCRYPT_SUCCESS(r))
    return false;

  return true;
}
#endif

#else

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

bool
hsk_randombytes(uint8_t *dst, size_t len) {
  int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

  if (fd == -1) {
    fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
    if (fd == -1)
      return false;
  }

  char *ptr = (char *)dst;
  size_t left = len;

  while (left > 0) {
    int bytes = read(fd, ptr, left);

    if (bytes <= 0) {
      close(fd);
      return false;
    }

    left -= bytes;
    ptr += bytes;
  }

  close(fd);
  return true;
}

#endif
