
#ifndef SOCKS5_ENUMS_HPP
#define SOCKS5_ENUMS_HPP

#include <cstdint>

namespace Socks5
{
enum class AddressType : uint8_t
{
  IP_V4 = 0x01,
  DOMAIN_NAME = 0x03,
  IP_V6 = 0x04
};


enum class AuthMethod : uint8_t
{
  NO_AUTHENTICATION = 0x00,
  GSSAPI = 0x01,
  USER_PASS = 0x02,
  NO_METHODS = 0xff
};


enum class ReplyCode : uint8_t
{
  SUCCEEDED = 0x00,
  GENERAL_SOCKS_FAILURE = 0x01,
  CONNECTION_NOT_ALLOWED_RULESET = 0x02,
  NETWORK_UNREACHABLE = 0x03,
  HOST_UNREACHABLE = 0x04,
  CONNECTION_REFUSED = 0x05,
  TTL_EXPIRED = 0x06,
  COMMAND_NOT_SUPPORTED = 0x07,
  ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
};


enum class Command : uint8_t
{
  CONNECT = 0x01,
  BIND = 0x02,
  UDP_ASSOCIATE = 0x03
};


enum class Error : uint8_t
{
  NO_ERROR = 0,
  INIT_SEND_ERROR = 1,
  INIT_RECEIVE_ERROR = 2,
  REQUEST_SEND_ERROR = 3,
  REPLY_RECEIVE_ERROR = 4,
};
}

#endif
