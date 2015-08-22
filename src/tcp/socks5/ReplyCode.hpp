
#ifndef SOCKS5_REPLY_CODE_HPP
#define SOCKS5_REPLY_CODE_HPP

#include <cstdint>

namespace Socks5
{
enum class ReplyCode : uint8_t
{
  succeeded = 0x00,
  general_socks_failure = 0x01,
  connection_not_allowed_ruleset = 0x02,
  network_unreachable = 0x03,
  host_unreachable = 0x04,
  connection_refused = 0x05,
  ttl_expired = 0x06,
  command_not_supported = 0x07,
  address_type_not_supported = 0x08,
};
}

#endif
