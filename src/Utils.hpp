
#ifndef UTILS_HPP
#define UTILS_HPP

#include "Constants.hpp"
#include <botan/rsa.h>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>

class Utils
{
 public:
  static std::vector<std::string> split(const char*, char token = ' ');
  static void stringReplace(std::string&,
                            const std::string&,
                            const std::string&);
  static bool strEndsWith(const std::string&, const std::string&);
  static bool strBeginsWith(const std::string&, const std::string&);
  static std::string trimString(const std::string&);

  static std::shared_ptr<Botan::RSA_PublicKey> BER64toRSA(const std::string&);
  static RSA_SIGNATURE decodeSignature(const std::string&);
  static std::shared_ptr<Botan::RSA_PrivateKey> loadKey(const std::string&);
  static std::shared_ptr<Botan::RSA_PrivateKey> loadOpenSSLRSA(
      const std::string&);

  static std::string getWorkingDirectory();
  static unsigned long decode64Size(size_t);
};

#endif
