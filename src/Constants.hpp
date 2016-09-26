
#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#include <array>

class Const
{
 public:
  // cryptography
  static const uint32_t RSA_LEN = 1024;
  static const uint32_t RSA_SIGNATURE_LEN = RSA_LEN / 8;
  static const uint32_t SHA256_LEN = 256 / 8;
  static const uint32_t SHA1_LEN = 160 / 8;

  // proof of work
  static const uint8_t POW_THRESHOLD_BYTES = 4;  // bytes that must be 0
  static const uint8_t POW_THRESHOLD = 0x80;     // final byte less than this

  // networking
  static const ushort SERVER_PORT = 9053;
  static const short TB_CONTROL_PORT = 9151;
};

typedef std::array<uint8_t, Const::SHA256_LEN> SHA256_HASH;
typedef std::array<uint8_t, Const::RSA_SIGNATURE_LEN> RSA_SIGNATURE;

struct UInt8Array
{
  const uint8_t* data;
  size_t length;
};

#endif
