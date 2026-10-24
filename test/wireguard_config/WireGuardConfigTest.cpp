#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <type_traits>

#include "WireGuardTransport/WireGuardConfig.h"

namespace {
constexpr char PRIVATE_KEY[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
constexpr char PUBLIC_KEY[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
constexpr char PRESHARED_KEY[] = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";

bool parse(WireGuardConfigParser& parser, const std::string& contents) {
  std::istringstream input(contents);
  std::string line;
  while (std::getline(input, line)) {
    if (!parser.parseLine(line)) return false;
  }
  return parser.finish();
}

std::string requiredConfig(const std::string& allowedIps = "0.0.0.0/0") {
  return std::string("[Interface]\nPrivateKey = ") + PRIVATE_KEY +
         "\nAddress = 10.7.0.4/32\nDNS = 10.7.0.1\n[Peer]\nPublicKey = " + PUBLIC_KEY +
         "\nEndpoint = vpn.example.test:51820\nAllowedIPs = " + allowedIps + "\n";
}
}  // namespace

static_assert(std::is_trivially_copyable_v<WireGuardConfigParser>);
static_assert(sizeof(WireGuardConfigParser) < 512);

TEST(WireGuardConfig, ParsesSupportedWgQuickSubset) {
  WireGuardConfigParser parser;
  const std::string config = std::string("# X4 Pro tunnel\n[Interface]\nPrivateKey = ") + PRIVATE_KEY +
                             "\nAddress = fd00::4/128, 10.7.0.4/32\nDNS = fd00::1, 10.7.0.1\nMTU = 1420\n"
                             "[Peer]\nPublicKey = " +
                             PUBLIC_KEY + "\nPresharedKey = " + PRESHARED_KEY +
                             "\nEndpoint = vpn.example.test:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n"
                             "PersistentKeepalive = 25\n";

  ASSERT_TRUE(parse(parser, config));
  const WireGuardConfig& parsed = parser.config();
  EXPECT_STREQ(parsed.privateKey, PRIVATE_KEY);
  EXPECT_STREQ(parsed.publicKey, PUBLIC_KEY);
  EXPECT_STREQ(parsed.presharedKey, PRESHARED_KEY);
  EXPECT_STREQ(parsed.endpointHost, "vpn.example.test");
  EXPECT_EQ(parsed.address, (std::array<uint8_t, 4>{10, 7, 0, 4}));
  EXPECT_EQ(parsed.dns, (std::array<uint8_t, 4>{10, 7, 0, 1}));
  EXPECT_EQ(parsed.endpointPort, 51820);
  EXPECT_EQ(parsed.persistentKeepalive, 25);
  EXPECT_TRUE(parsed.hasPresharedKey);
  EXPECT_TRUE(parsed.hasDns);
}

TEST(WireGuardConfig, OptionalPeerEntriesDefaultOff) {
  WireGuardConfigParser parser;
  ASSERT_TRUE(parse(parser, requiredConfig()));
  EXPECT_FALSE(parser.config().hasPresharedKey);
  EXPECT_EQ(parser.config().persistentKeepalive, 0);
}

TEST(WireGuardConfig, RequiresTunnelDns) {
  WireGuardConfigParser parser;
  std::string config = requiredConfig();
  const size_t dns = config.find("DNS = ");
  config.erase(dns, config.find('\n', dns) - dns + 1);
  EXPECT_FALSE(parse(parser, config));
  EXPECT_EQ(parser.error(), WireGuardConfigError::MissingRequiredEntry);

  WireGuardConfigParser unspecifiedDns;
  config = requiredConfig();
  config.replace(config.find("10.7.0.1"), sizeof("10.7.0.1") - 1, "0.0.0.0");
  EXPECT_FALSE(parse(unspecifiedDns, config));
  EXPECT_EQ(unspecifiedDns.error(), WireGuardConfigError::InvalidAddress);
}

TEST(WireGuardConfig, RequiresFullIpv4Route) {
  WireGuardConfigParser parser;
  EXPECT_FALSE(parse(parser, requiredConfig("10.0.0.0/8")));
  EXPECT_EQ(parser.error(), WireGuardConfigError::InvalidAllowedIps);
}

TEST(WireGuardConfig, RejectsSecondPeer) {
  WireGuardConfigParser parser;
  EXPECT_FALSE(parse(parser, requiredConfig() + "[Peer]\nPublicKey = " + PUBLIC_KEY + "\n"));
  EXPECT_EQ(parser.error(), WireGuardConfigError::MultiplePeers);
}

TEST(WireGuardConfig, RejectsInvalidKeyAndEndpoint) {
  WireGuardConfigParser badKey;
  std::string config = requiredConfig();
  config.replace(config.find(PRIVATE_KEY), sizeof(PRIVATE_KEY) - 1, "short");
  EXPECT_FALSE(parse(badKey, config));
  EXPECT_EQ(badKey.error(), WireGuardConfigError::InvalidKey);

  WireGuardConfigParser badEndpoint;
  config = requiredConfig();
  config.replace(config.find("vpn.example.test:51820"), sizeof("vpn.example.test:51820") - 1, "vpn.example.test");
  EXPECT_FALSE(parse(badEndpoint, config));
  EXPECT_EQ(badEndpoint.error(), WireGuardConfigError::InvalidEndpoint);

  WireGuardConfigParser unspecifiedEndpoint;
  config = requiredConfig();
  config.replace(config.find("vpn.example.test"), sizeof("vpn.example.test") - 1, "0.0.0.0");
  EXPECT_FALSE(parse(unspecifiedEndpoint, config));
  EXPECT_EQ(unspecifiedEndpoint.error(), WireGuardConfigError::InvalidEndpoint);
}

TEST(WireGuardConfig, RejectsUnknownWgQuickScripts) {
  WireGuardConfigParser parser;
  std::string config = requiredConfig();
  config.insert(config.find("[Peer]"), "PostUp = ip rule add table 100\n");
  EXPECT_FALSE(parse(parser, config));
  EXPECT_EQ(parser.error(), WireGuardConfigError::InvalidEntry);
}
