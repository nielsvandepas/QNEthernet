#include <Arduino.h>
#include <Entropy.h>

extern "C" {
  #include "mbedtls/entropy.h"
  #include "mbedtls/entropy_poll.h"
}

MBEDTLSFLASHMEM int mbedtls_hardware_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen ) {
  for (size_t i = 0; i < len; ++i) {
    while (!Entropy.available());
    output[i] = Entropy.random() >> 24;
  }

  *olen = len;

  return 0;
}
