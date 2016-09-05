
#ifndef UTILS_HPP
#define UTILS_HPP

#include <botan/rsa.h>
#include <cstdint>
#include <vector>
#include <string>

class Utils
{
 public:
  static uint32_t arrayToUInt32(const uint8_t*, int32_t);
  static char* getAsHex(const uint8_t*, int);
  static bool isPowerOfTwo(std::size_t);

  static unsigned long decode64Estimation(unsigned long);

  static void stringReplace(std::string&,
                            const std::string&,
                            const std::string&);
  static bool strEndsWith(const std::string&, const std::string&);
  static bool strBeginsWith(const std::string&, const std::string&);
  static std::string trimString(const std::string&);

  static Botan::RSA_PublicKey* base64ToRSA(const std::string&);
  static Botan::RSA_PrivateKey* loadKey(const std::string&);
  static Botan::RSA_PrivateKey* loadOpenSSLRSA(const std::string&,
                                               Botan::RandomNumberGenerator&);

  static void hex2bin(const uint8_t*, uint8_t*);
  static uint8_t char2int(const uint8_t);
  static std::vector<std::string> split(const char*, char token = ' ');
};

#endif
