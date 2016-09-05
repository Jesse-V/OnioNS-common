
#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#include <array>

class Const
{
 public:
  static const uint32_t RSA_LEN = 1024;
  static const uint32_t SIGNATURE_LEN = RSA_LEN / 8;
  static const uint32_t SHA256_LEN = 256 / 8;
  static const uint32_t SHA1_LEN = 160 / 8;
  static const uint8_t RECORD_NONCE_LEN = 4;

  static const uint32_t ED25519_SIG_LEN = 64;
  static const uint32_t ED25519_KEY_LEN = 32;

  static const ushort SERVER_PORT = 9053;
  static const short TB_CONTROL_PORT = 9151;
};

typedef std::array<uint8_t, Const::SHA256_LEN> SHA256_HASH;
typedef std::array<uint8_t, Const::ED25519_KEY_LEN> ED_KEY;
typedef std::array<uint8_t, Const::ED25519_SIG_LEN> ED_SIGNATURE;

#endif
