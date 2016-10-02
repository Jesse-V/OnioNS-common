
#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#include <array>
#include <bitset>
#include <memory>

class Const
{
 public:
  // cryptography
  static const size_t RSA_KEY_LEN = 1024;
  static const size_t RSA_SIG_LEN = RSA_KEY_LEN / 8;
  static const size_t SHA256_LEN = 256 / 8;
  static const size_t SHA1_LEN = 160 / 8;
  static const size_t EdDSA_KEY_LEN = 32;
  static const size_t EdDSA_SIG_LEN = 64;

  // proof of work
  // static constexpr std::bitset<16> set = 0xfa2;
  static const uint32_t POW_WORD_0 = 1 << 8;
  // static const uint32_t POW_WORD_1 = 0x80;

  // networking
  static const ushort SERVER_PORT = 9053;
  static const short TB_CONTROL_PORT = 9151;
};

// typedef std::shared_ptr<std::array<uint8_t, Const::SHA256_LEN>> SHA256_HASH;
typedef std::shared_ptr<std::array<uint8_t, Const::RSA_SIG_LEN>> RSA_SIGNATURE;
typedef std::shared_ptr<std::array<uint8_t, Const::EdDSA_KEY_LEN>> EdDSA_KEY;
typedef std::shared_ptr<std::array<uint8_t, Const::EdDSA_SIG_LEN>> EdDSA_SIG;

#endif
