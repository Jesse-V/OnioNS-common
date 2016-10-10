
#include "Utils.hpp"
#include "Log.hpp"
#include <botan/pem.h>
#include <botan/base64.h>
#include <botan/auto_rng.h>
#include <sys/stat.h>


std::vector<std::string> Utils::split(const char* str, char c)
{  // https://stackoverflow.com/questions/53849

  std::vector<std::string> result;

  do
  {
    const char* begin = str;
    while (*str != c && *str)
      str++;

    result.push_back(std::string(begin, str));
  } while (0 != *str++);

  return result;
}



// https://stackoverflow.com/questions/1494399/how-do-i-search-find-and-replace-in-a-standard-string
void Utils::stringReplace(std::string& str,
                          const std::string& find,
                          const std::string& replace)
{
  size_t pos = 0;
  while ((pos = str.find(find, pos)) != std::string::npos)
  {
    str.replace(pos, find.length(), replace);
    pos += replace.length();
  }
}



// https://stackoverflow.com/questions/874134/
bool Utils::strEndsWith(const std::string& str, const std::string& end)
{
  if (end.size() > str.size())
    return false;
  return std::equal(end.rbegin(), end.rend(), str.rbegin());
}



bool Utils::strBeginsWith(const std::string& str, const std::string& begin)
{  // https://stackoverflow.com/questions/931827/
  return str.compare(0, begin.length(), begin) == 0;
}



std::string Utils::trimString(const std::string& str)
{  // https://stackoverflow.com/questions/216823
  std::string s(str);
  s.erase(s.begin(),
          std::find_if(s.begin(), s.end(),
                       std::not1(std::ptr_fun<int, int>(std::isspace))));
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       std::not1(std::ptr_fun<int, int>(std::isspace)))
              .base(),
          s.end());
  return s;
}



std::vector<uint8_t> Utils::decodeBase64(const std::string& b64, size_t max)
{
  std::vector<uint8_t> decoded;
  decoded.reserve(decode64Size(b64.length()));
  size_t len = Botan::base64_decode(decoded.data(), b64, false);

  if (len > max)
  {
    Log::get().warn("Base64 decoded to " + std::to_string(len) +
                    " bytes, expected " + std::to_string(max));
    decoded.clear();
  }

  return decoded;
}



std::shared_ptr<Botan::RSA_PrivateKey> Utils::decodeRSA(const std::string& pem)
{
  static Botan::AutoSeeded_RNG rng;

  try
  {
    // attempt reading key as standardized PKCS8 format
    Log::get().debug("Attempting to decode PKCS8-formatted RSA key... ");

    // todo: adapt the code from Record's constructor
    Botan::DataSource_Memory keyMem(pem);
    auto key = Botan::PKCS8::load_key(keyMem, rng);
    auto rsaKey = dynamic_cast<Botan::RSA_PrivateKey*>(key);
    if (!rsaKey)
      Log::get().error("The loaded key is not a RSA key!");

    Log::get().debug("Decode complete.");
    return std::make_shared<Botan::RSA_PrivateKey>(*rsaKey);
  }
  catch (const Botan::Decoding_Error&)
  {
    return Utils::decodeOpenSSLRSA(pem);
  }
  catch (const Botan::Stream_IO_Error& err)
  {
    Log::get().error(err.what());
  }

  return NULL;
}



// http://botan.randombit.net/faq.html#how-do-i-load-this-key-generated-by-openssl-into-botan
// http://lists.randombit.net/pipermail/botan-devel/2010-June/001157.html
// http://lists.randombit.net/pipermail/botan-devel/attachments/20100611/1d8d870a/attachment.cpp
std::shared_ptr<Botan::RSA_PrivateKey> Utils::decodeOpenSSLRSA(
    const std::string& pemStr)
{
  Log::get().debug("Decoding OpenSSL-formatted RSA key...");

  static Botan::AutoSeeded_RNG rng;
  Botan::DataSource_Memory in(pemStr);
  Botan::DataSource_Memory key_bits(
      Botan::PEM_Code::decode_check_label(in, "RSA PRIVATE KEY"));

  // Botan::u32bit version;
  size_t version;
  Botan::BigInt n, e, d, p, q;

  Botan::BER_Decoder(key_bits)
      .start_cons(Botan::SEQUENCE)
      .decode(version)
      .decode(n)
      .decode(e)
      .decode(d)
      .decode(p)
      .decode(q);

  if (version != 0)
    return NULL;

  Log::get().debug("Succesfully decoded OpenSSL RSA key.");
  return std::make_shared<Botan::RSA_PrivateKey>(rng, p, q, e, d, n);
}



std::string Utils::getWorkingDirectory()
{
  // std::string workingDir(getpwuid(getuid())->pw_dir);
  // workingDir += "/.OnioNS/";

  std::string workingDir = ".OnioNS";

  if (mkdir(workingDir.c_str(), 0750) == 0)
    Log::get().notice("Working directory successfully created.");

  return workingDir;
}



unsigned long Utils::decode64Size(size_t inSize)
{  // https://stackoverflow.com/questions/1533113/
  return ((inSize * 4) / 3) + (inSize / 96) + 6;
}
