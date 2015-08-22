
#ifndef SOCKS5_ERROR_HPP
#define SOCKS5_ERROR_HPP

#include <cstdint>

namespace Socks5
{
enum class Error : uint8_t
{
  no_error = 0,
  init_send_error = 1,
  init_receive_error = 2,
  request_send_error = 3,
  reply_receive_error = 4,
};
}

#endif
