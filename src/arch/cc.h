// SPDX-FileCopyrightText: (c) 2021 Shawn Silverman <shawn@pobox.com>
// SPDX-License-Identifier: MIT

// lwIP configuration for QNEthernet library on Teensy 4.1.
// This file is part of the QNEthernet library.

#ifndef LWIPTEENSY_ARCH_CC_H_
#define LWIPTEENSY_ARCH_CC_H_

#define LWIP_RAND() ((u32_t)rand())

#include "lwiplog.h"
#define LWIP_PLATFORM_DIAG(x) do {lwip_log x;} while(0)

#endif  // LWIPTEENSY_ARCH_CC_H_
