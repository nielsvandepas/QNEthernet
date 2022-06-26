#include <Arduino.h>

extern "C" {
  #include "lwiplog.h"
}

void lwip_log(const char *format, ...) {
  Serial.printf(format);
}
