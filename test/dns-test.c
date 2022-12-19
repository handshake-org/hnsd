#include <assert.h>
#include <stdio.h>

#include "dns.h"

static void
test_hsk_dns_is_subdomain() {
  assert(hsk_dns_is_subdomain(".", "com."));
  assert(hsk_dns_is_subdomain("com.", "com."));

  assert(!hsk_dns_is_subdomain("com.", "xcom."));
  assert(hsk_dns_is_subdomain("com.", "x.com."));

  assert(hsk_dns_is_subdomain("com.", "google.com."));
  assert(!hsk_dns_is_subdomain("google.com.", "com."));
  assert(hsk_dns_is_subdomain("google.com.", "mail.google.com."));
  assert(hsk_dns_is_subdomain("com.", "mail.google.com."));
  assert(hsk_dns_is_subdomain("com.", "images.mail.google.com."));
  assert(hsk_dns_is_subdomain("mail.google.com.", "images.mail.google.com."));
  assert(!hsk_dns_is_subdomain("images.mail.google.com.", "mail.google.com."));

  // 63-char labels
  assert(hsk_dns_is_subdomain(
    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.",
    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd."));
}

void
test_dns() {
  printf(" test_hsk_dns_name_cmp\n");
  test_hsk_dns_is_subdomain();
}
