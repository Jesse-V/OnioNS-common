
#ifndef SOCKS5_COMMAND_HPP
#define SOCKS5_COMMAND_HPP

#include <cstdint>

namespace Socks5
{
enum class Command : uint8_t
{
  connect = 0x01,
  bind = 0x02,
  udp_associate = 0x03
};
}

#endif
