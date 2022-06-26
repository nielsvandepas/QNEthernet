// SPDX-FileCopyrightText: (c) 2021-2022 Shawn Silverman <shawn@pobox.com>
// SPDX-License-Identifier: MIT

// QNEthernetServer.h defines the TCP server interface.
// This file is part of the QNEthernet library.

#ifndef QNE_ETHERNETSERVER_H_
#define QNE_ETHERNETSERVER_H_

#include <Print.h>
#include <Server.h>

#include "QNEthernetClient.h"
#include "lwip/opt.h"

namespace qindesign {
namespace network {

class EthernetServer final : public Server {
 public:
  EthernetServer(uint16_t port);
  #ifdef USE_TLS
  EthernetServer(uint16_t port, bool tls);
  #endif
  ~EthernetServer();

  // Returns the maximum number of TCP listeners.
  static constexpr int maxListeners() {
    return MEMP_NUM_TCP_PCB_LISTEN;
  }

  // Returns the port.
  uint16_t port() const {
    return port_;
  }

  #ifdef USE_TLS
  void setSigning(uint8_t *cert, size_t certLength, uint8_t *key, size_t keyLength, uint8_t *password, size_t passwordLength);
  #endif

  // Starts listening on the server port. This calls begin(false).
  void begin() override;

  // Starts listening on the server port and sets the SO_REUSEADDR socket option
  // according to the `reuse` parameter.
  void begin(bool reuse);

  bool end() const;

  EthernetClient accept() const;
  EthernetClient available() const;

  // Bring Print::write functions into scope
  using Print::write;

  size_t write(uint8_t b) override;
  size_t write(const uint8_t *buffer, size_t size) override;

  // Returns the minimum availability of all the connections, or zero if there
  // are no connections.
  int availableForWrite() override;

  void flush() override;

  operator bool();

 private:
  const uint16_t port_;
  bool listening_;
  const bool tls_;
  uint8_t *cert;
  size_t certLength;
  uint8_t *key;
  size_t keyLength;
  uint8_t *password;
  size_t passwordLength;
};

}  // namespace network
}  // namespace qindesign

#endif  // QNE_ETHERNETSERVER_H_
