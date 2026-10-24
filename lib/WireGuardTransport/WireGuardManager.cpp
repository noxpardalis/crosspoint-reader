#include "WireGuardManager.h"

#include <Logging.h>

#if defined(CROSSPOINT_ENABLE_WIREGUARD)
#include <HalMemory.h>
#include <HalStorage.h>
#include <TrustedTime.h>
#include <WiFi.h>
#include <lwip/tcpip.h>

#include <cstring>
#include <type_traits>
#endif

WireGuardManager& WireGuardManager::getInstance() {
  static WireGuardManager instance;
  return instance;
}

#if defined(CROSSPOINT_ENABLE_WIREGUARD)
namespace {
constexpr size_t MAX_CONFIG_BYTES = 2048;
constexpr size_t LINE_CAPACITY = 192;
constexpr uint32_t TIME_SYNC_TIMEOUT_MS = 15000;
constexpr uint32_t HANDSHAKE_TIMEOUT_MS = 15000;

static_assert(std::is_trivially_copyable_v<WireGuardConfigParser>);

void secureClear(void* memory, const size_t bytes) {
  volatile uint8_t* output = static_cast<volatile uint8_t*>(memory);
  for (size_t i = 0; i < bytes; ++i) output[i] = 0;
}
}  // namespace

bool WireGuardManager::loadConfig() {
  clearConfig();

  HalFile file;
  if (!Storage.openFileForRead("WG", CONFIG_PATH, file)) return false;
  const size_t fileSize = file.fileSize();
  if (fileSize == 0 || fileSize > MAX_CONFIG_BYTES) {
    LOG_ERR("WG", "Config must be 1..%zu bytes", MAX_CONFIG_BYTES);
    return false;
  }

  char line[LINE_CAPACITY] = {};
  size_t lineLength = 0;
  size_t lineNumber = 1;
  while (file.available()) {
    const int value = file.read();
    if (value < 0) {
      LOG_ERR("WG", "Could not read config line %zu", lineNumber);
      return false;
    }
    if (value == '\r') continue;
    if (value == '\n') {
      if (!parser.parseLine(std::string_view(line, lineLength))) {
        LOG_ERR("WG", "Invalid config at line %zu (error %u)", lineNumber, static_cast<unsigned>(parser.error()));
        return false;
      }
      lineLength = 0;
      ++lineNumber;
      continue;
    }
    if (lineLength + 1 >= sizeof(line)) {
      LOG_ERR("WG", "Config line %zu exceeds %zu bytes", lineNumber, sizeof(line) - 1);
      return false;
    }
    line[lineLength++] = static_cast<char>(value);
  }
  if (lineLength > 0 && !parser.parseLine(std::string_view(line, lineLength))) {
    LOG_ERR("WG", "Invalid config at line %zu (error %u)", lineNumber, static_cast<unsigned>(parser.error()));
    return false;
  }
  if (!parser.finish()) {
    LOG_ERR("WG", "Incomplete config (error %u)", static_cast<unsigned>(parser.error()));
    return false;
  }
  return true;
}

void WireGuardManager::saveDnsServers() {
  LOCK_TCPIP_CORE();
  for (size_t i = 0; i < DNS_MAX_SERVERS; ++i) ip_addr_copy(previousDns[i], *dns_getserver(i));
  UNLOCK_TCPIP_CORE();
}

void WireGuardManager::applyTunnelDns(const WireGuardConfig& config) {
  if (!config.hasDns) return;
  const ip_addr_t dns = IPADDR4_INIT_BYTES(config.dns[0], config.dns[1], config.dns[2], config.dns[3]);
  LOCK_TCPIP_CORE();
  dns_setserver(0, &dns);
  UNLOCK_TCPIP_CORE();
}

void WireGuardManager::restoreDnsServers() {
  LOCK_TCPIP_CORE();
  for (size_t i = 0; i < DNS_MAX_SERVERS; ++i) dns_setserver(i, &previousDns[i]);
  UNLOCK_TCPIP_CORE();
}

void WireGuardManager::clearConfig() { secureClear(&parser, sizeof(parser)); }
#endif

bool WireGuardManager::prepare(const bool enabled) {
#if !defined(CROSSPOINT_ENABLE_WIREGUARD)
  (void)enabled;
  return true;
#else
  if (!enabled || active) return true;
  if (WiFi.status() != WL_CONNECTED) {
    LOG_ERR("WG", "Cannot start tunnel without Wi-Fi");
    return false;
  }
  if (!loadConfig()) {
    clearConfig();
    return false;
  }

  // A new key may handshake before the asynchronous join-time SNTP query has
  // answered. WireGuard timestamps need a trustworthy monotonic starting point.
  if (trustedtime::trustedNow() == 0 && !trustedtime::syncNow(TIME_SYNC_TIMEOUT_MS)) {
    LOG_ERR("WG", "Could not establish trusted time for handshake");
    clearConfig();
    return false;
  }

  const WireGuardConfig& config = parser.config();
  const IPAddress localIp(config.address[0], config.address[1], config.address[2], config.address[3]);
  const char* presharedKey = config.hasPresharedKey ? config.presharedKey : nullptr;
  const auto before = HalMemory::getInternalHeap();
  saveDnsServers();
  if (!tunnel.beginAWG(localIp, config.privateKey, config.endpointHost, config.publicKey, config.endpointPort,
                       presharedKey, config.persistentKeepalive,
                       /*jc=*/0, /*jmin=*/0, /*jmax=*/0, /*s1=*/0, /*s2=*/0, /*s3=*/0, /*s4=*/0,
                       /*headerProtectionKey=*/nullptr)) {
    LOG_ERR("WG", "Could not initialize tunnel");
    clearConfig();
    return false;
  }
  if (!tunnel.waitForHandshake(HANDSHAKE_TIMEOUT_MS)) {
    LOG_ERR("WG", "Peer handshake timed out");
    tunnel.end();
    restoreDnsServers();
    clearConfig();
    return false;
  }

  applyTunnelDns(config);
  clearConfig();
  active = true;
  const auto after = HalMemory::getInternalHeap();
  LOG_INF("WG", "Tunnel ready (internal heap %zu -> %zu, largest block %zu)", before.freeBytes, after.freeBytes,
          after.largestBlockBytes);
  return true;
#endif
}

void WireGuardManager::shutdown() {
#if defined(CROSSPOINT_ENABLE_WIREGUARD)
  if (active) {
    tunnel.end();
    restoreDnsServers();
    active = false;
    const auto heap = HalMemory::getInternalHeap();
    LOG_INF("WG", "Tunnel stopped (internal heap %zu, largest block %zu)", heap.freeBytes, heap.largestBlockBytes);
  }
  clearConfig();
#else
  active = false;
#endif
}
