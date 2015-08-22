
#ifndef SOCKS5_AUTH_METHOD_HPP
#define SOCKS5_AUTH_METHOD_HPP

#include <cstdint>

namespace Socks5
{
enum class AuthMethod : uint8_t
{
  no_authentication = 0x00,
  gssapi = 0x01,
  user_pass = 0x02,
  no_methods = 0xff
};
}

#endif
