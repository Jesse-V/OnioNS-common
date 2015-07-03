
#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#include <string>

class Const
{
 public:
  static const uint32_t RSA_LEN = 1024;
  static const uint32_t SIGNATURE_LEN = RSA_LEN / 8;
  // static const uint32_t SHA256_LEN = 256 / 8;
  static const uint32_t SHA384_LEN = 384 / 8;
  static const uint32_t SHA1_LEN = 160 / 8;

  static const ushort IPC_PORT = 9053;
  static const ushort SERVER_PORT = 10053;
};

#endif
