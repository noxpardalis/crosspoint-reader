#include "WireGuardConfig.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstring>

namespace {
std::string_view trim(std::string_view value) {
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.remove_prefix(1);
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.remove_suffix(1);
  return value;
}

bool equalsIgnoreCase(const std::string_view left, const std::string_view right) {
  if (left.size() != right.size()) return false;
  for (size_t i = 0; i < left.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(left[i])) != std::tolower(static_cast<unsigned char>(right[i]))) {
      return false;
    }
  }
  return true;
}

bool copyString(const std::string_view source, char* destination, const size_t capacity) {
  if (source.empty() || source.size() >= capacity) return false;
  memcpy(destination, source.data(), source.size());
  destination[source.size()] = '\0';
  return true;
}

bool validKey(const std::string_view key) {
  if (key.size() != 44 || key.back() != '=') return false;
  for (size_t i = 0; i + 1 < key.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(key[i]);
    if (!std::isalnum(c) && c != '+' && c != '/') return false;
  }
  return true;
}

bool parseUnsigned(const std::string_view text, unsigned& value) {
  if (text.empty()) return false;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
  return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

bool parseIpv4(const std::string_view text, std::array<uint8_t, 4>& address) {
  size_t start = 0;
  for (size_t i = 0; i < address.size(); ++i) {
    const size_t end = i + 1 == address.size() ? text.size() : text.find('.', start);
    if (end == std::string_view::npos || end == start) return false;
    unsigned octet = 0;
    if (!parseUnsigned(text.substr(start, end - start), octet) || octet > 255) return false;
    address[i] = static_cast<uint8_t>(octet);
    start = end + 1;
  }
  return start == text.size() + 1;
}

bool isUnspecified(const std::array<uint8_t, 4>& address) {
  return std::all_of(address.begin(), address.end(), [](const uint8_t octet) { return octet == 0; });
}

bool parseAddress(const std::string_view value, std::array<uint8_t, 4>& address) {
  size_t start = 0;
  while (start < value.size()) {
    const size_t comma = value.find(',', start);
    const std::string_view item =
        trim(value.substr(start, comma == std::string_view::npos ? value.size() - start : comma - start));
    const size_t slash = item.find('/');
    const std::string_view ip = slash == std::string_view::npos ? item : item.substr(0, slash);
    unsigned prefix = 32;
    if (slash != std::string_view::npos && !parseUnsigned(item.substr(slash + 1), prefix)) return false;
    if (prefix <= 32 && parseIpv4(ip, address) && !isUnspecified(address)) return true;
    if (comma == std::string_view::npos) break;
    start = comma + 1;
  }
  return false;
}

bool parseDns(const std::string_view value, std::array<uint8_t, 4>& dns) {
  size_t start = 0;
  while (start < value.size()) {
    const size_t comma = value.find(',', start);
    const std::string_view item =
        trim(value.substr(start, comma == std::string_view::npos ? value.size() - start : comma - start));
    if (parseIpv4(item, dns) && !isUnspecified(dns)) return true;
    if (comma == std::string_view::npos) break;
    start = comma + 1;
  }
  return false;
}

bool validEndpointHost(const std::string_view host) {
  if (host.empty() || host == "0.0.0.0") return false;
  return std::all_of(host.begin(), host.end(), [](const char value) {
    const unsigned char c = static_cast<unsigned char>(value);
    return std::isalnum(c) || c == '.' || c == '-';
  });
}
}  // namespace

bool WireGuardConfigParser::fail(const WireGuardConfigError error) {
  if (parseError == WireGuardConfigError::None) parseError = error;
  return false;
}

bool WireGuardConfigParser::parseInterfaceEntry(const std::string_view key, const std::string_view value) {
  if (equalsIgnoreCase(key, "PrivateKey")) {
    if (!validKey(value) || !copyString(value, parsed.privateKey, sizeof(parsed.privateKey))) {
      return fail(WireGuardConfigError::InvalidKey);
    }
    sawPrivateKey = true;
    return true;
  }
  if (equalsIgnoreCase(key, "Address")) {
    if (!parseAddress(value, parsed.address)) return fail(WireGuardConfigError::InvalidAddress);
    sawAddress = true;
    return true;
  }
  if (equalsIgnoreCase(key, "DNS")) {
    if (!parseDns(value, parsed.dns)) return fail(WireGuardConfigError::InvalidAddress);
    parsed.hasDns = true;
    return true;
  }
  // ListenPort and MTU do not change this client-only, fixed-MTU tunnel.
  if (equalsIgnoreCase(key, "ListenPort") || equalsIgnoreCase(key, "MTU")) return true;
  return fail(WireGuardConfigError::InvalidEntry);
}

bool WireGuardConfigParser::parsePeerEntry(const std::string_view key, const std::string_view value) {
  if (equalsIgnoreCase(key, "PublicKey")) {
    if (!validKey(value) || !copyString(value, parsed.publicKey, sizeof(parsed.publicKey))) {
      return fail(WireGuardConfigError::InvalidKey);
    }
    sawPublicKey = true;
    return true;
  }
  if (equalsIgnoreCase(key, "PresharedKey")) {
    if (!validKey(value) || !copyString(value, parsed.presharedKey, sizeof(parsed.presharedKey))) {
      return fail(WireGuardConfigError::InvalidKey);
    }
    parsed.hasPresharedKey = true;
    return true;
  }
  if (equalsIgnoreCase(key, "Endpoint")) {
    const size_t colon = value.rfind(':');
    if (colon == std::string_view::npos || value.find(':') != colon) {
      return fail(WireGuardConfigError::InvalidEndpoint);
    }
    const std::string_view host = trim(value.substr(0, colon));
    unsigned port = 0;
    if (!validEndpointHost(host) || !parseUnsigned(trim(value.substr(colon + 1)), port) || port == 0 ||
        port > UINT16_MAX || !copyString(host, parsed.endpointHost, sizeof(parsed.endpointHost))) {
      return fail(WireGuardConfigError::InvalidEndpoint);
    }
    parsed.endpointPort = static_cast<uint16_t>(port);
    sawEndpoint = true;
    return true;
  }
  if (equalsIgnoreCase(key, "AllowedIPs")) {
    size_t start = 0;
    while (start < value.size()) {
      const size_t comma = value.find(',', start);
      const std::string_view item =
          trim(value.substr(start, comma == std::string_view::npos ? value.size() - start : comma - start));
      if (item == "0.0.0.0/0") routesAllIpv4 = true;
      if (comma == std::string_view::npos) break;
      start = comma + 1;
    }
    return true;
  }
  if (equalsIgnoreCase(key, "PersistentKeepalive")) {
    unsigned seconds = 0;
    if (!parseUnsigned(value, seconds) || seconds > UINT16_MAX) {
      return fail(WireGuardConfigError::InvalidKeepalive);
    }
    parsed.persistentKeepalive = static_cast<uint16_t>(seconds);
    return true;
  }
  return fail(WireGuardConfigError::InvalidEntry);
}

bool WireGuardConfigParser::parseLine(std::string_view line) {
  if (parseError != WireGuardConfigError::None) return false;
  const size_t comment = line.find_first_of("#;");
  if (comment != std::string_view::npos) line = line.substr(0, comment);
  line = trim(line);
  if (line.empty()) return true;

  if (line.front() == '[') {
    if (line.back() != ']') return fail(WireGuardConfigError::InvalidSection);
    const std::string_view name = trim(line.substr(1, line.size() - 2));
    if (equalsIgnoreCase(name, "Interface")) {
      if (sawInterface || sawPeer) return fail(WireGuardConfigError::InvalidSection);
      sawInterface = true;
      section = Section::Interface;
      return true;
    }
    if (equalsIgnoreCase(name, "Peer")) {
      if (!sawInterface) return fail(WireGuardConfigError::InvalidSection);
      if (sawPeer) return fail(WireGuardConfigError::MultiplePeers);
      sawPeer = true;
      section = Section::Peer;
      return true;
    }
    return fail(WireGuardConfigError::InvalidSection);
  }

  const size_t equals = line.find('=');
  if (equals == std::string_view::npos) return fail(WireGuardConfigError::InvalidEntry);
  const std::string_view key = trim(line.substr(0, equals));
  const std::string_view value = trim(line.substr(equals + 1));
  if (key.empty() || value.empty()) return fail(WireGuardConfigError::InvalidEntry);

  switch (section) {
    case Section::None:
      return fail(WireGuardConfigError::InvalidSection);
    case Section::Interface:
      return parseInterfaceEntry(key, value);
    case Section::Peer:
      return parsePeerEntry(key, value);
  }
  return fail(WireGuardConfigError::InvalidSection);
}

bool WireGuardConfigParser::finish() {
  if (parseError != WireGuardConfigError::None) return false;
  if (!sawPrivateKey || !sawAddress || !sawPublicKey || !sawEndpoint) {
    return fail(WireGuardConfigError::MissingRequiredEntry);
  }
  if (!parsed.hasDns) return fail(WireGuardConfigError::MissingRequiredEntry);
  if (!routesAllIpv4) return fail(WireGuardConfigError::InvalidAllowedIps);
  return true;
}
