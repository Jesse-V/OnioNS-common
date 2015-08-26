
#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#include <array>

class Const
{
 public:
  static const uint32_t RSA_LEN = 1024;
  static const uint32_t SIGNATURE_LEN = RSA_LEN / 8;
  static const uint32_t SHA384_LEN = 384 / 8;
  static const uint32_t SHA1_LEN = 160 / 8;

  static const uint32_t ED25519_SIG_LEN = 64;
  static const uint32_t ED25519_KEY_LEN = 32;

  static const ushort IPC_PORT = 9053;
  static const ushort SERVER_PORT = 10053;
};

typedef std::array<uint8_t, Const::SHA384_LEN> SHA384_HASH;
typedef std::array<uint8_t, Const::ED25519_KEY_LEN> ED_KEY;
typedef std::array<uint8_t, Const::ED25519_SIG_LEN> ED_SIGNATURE;

#endif
