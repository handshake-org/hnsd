#include <stdio.h>
#include <stdint.h>

#include "hnsd-test.h"

void
print_array(uint8_t *arr, size_t size){
  for (int i = 0; i < size; i++) {
    printf("%x", arr[i]);
  }
  printf("\n");
}

int
main() {
  printf("Testing hnsd...\n");

  printf("test_base32\n");
  test_base32();

  printf("test_dns\n");
  test_dns();

  printf("test_resource\n");
  test_resource();

  printf("ok\n");

  return 0;
}
