#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

enum class WireGuardConfigError : uint8_t {
  None,
  InvalidSection,
  MultiplePeers,
  InvalidEntry,
  InvalidKey,
  InvalidAddress,
  InvalidEndpoint,
  InvalidAllowedIps,
  InvalidKeepalive,
  MissingRequiredEntry,
};

struct WireGuardConfig {
  static constexpr size_t KEY_CAPACITY = 45;
  static constexpr size_t ENDPOINT_HOST_CAPACITY = 128;

  char privateKey[KEY_CAPACITY] = {};
  char publicKey[KEY_CAPACITY] = {};
  char presharedKey[KEY_CAPACITY] = {};
  char endpointHost[ENDPOINT_HOST_CAPACITY] = {};
  std::array<uint8_t, 4> address = {};
  std::array<uint8_t, 4> dns = {};
  uint16_t endpointPort = 0;
  uint16_t persistentKeepalive = 0;
  bool hasPresharedKey = false;
  bool hasDns = false;
};

class WireGuardConfigParser {
 public:
  bool parseLine(std::string_view line);
  bool finish();

  const WireGuardConfig& config() const { return parsed; }
  WireGuardConfigError error() const { return parseError; }

 private:
  enum class Section : uint8_t { None, Interface, Peer };

  WireGuardConfig parsed;
  Section section = Section::None;
  WireGuardConfigError parseError = WireGuardConfigError::None;
  bool sawInterface = false;
  bool sawPeer = false;
  bool sawPrivateKey = false;
  bool sawAddress = false;
  bool sawPublicKey = false;
  bool sawEndpoint = false;
  bool routesAllIpv4 = false;

  bool fail(WireGuardConfigError error);
  bool parseInterfaceEntry(std::string_view key, std::string_view value);
  bool parsePeerEntry(std::string_view key, std::string_view value);
};
