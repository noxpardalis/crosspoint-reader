#pragma once

#include "WireGuardConfig.h"

#if defined(CROSSPOINT_ENABLE_WIREGUARD)
#include <WireGuard-ESP32.h>
#include <lwip/dns.h>
#endif

class WireGuardManager {
 public:
  static constexpr const char* CONFIG_PATH = "/.crosspoint/wireguard.conf";

  static WireGuardManager& getInstance();

  // Disabled is a successful no-op. When enabled, this loads the SD config,
  // establishes a handshake, and changes the default IPv4 route.
  bool prepare(bool enabled);
  void shutdown();
  bool isActive() const { return active; }

 private:
  WireGuardManager() = default;
  ~WireGuardManager() = default;
  WireGuardManager(const WireGuardManager&) = delete;
  WireGuardManager& operator=(const WireGuardManager&) = delete;

#if defined(CROSSPOINT_ENABLE_WIREGUARD)
  bool loadConfig();
  void saveDnsServers();
  void applyTunnelDns(const WireGuardConfig& config);
  void restoreDnsServers();
  void clearConfig();

  WireGuardConfigParser parser;
  WireGuard tunnel;
  ip_addr_t previousDns[DNS_MAX_SERVERS] = {};
#endif
  bool active = false;
};

#define WIREGUARD_TUNNEL WireGuardManager::getInstance()
