
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
bool Utils::strEndsWith(const std::string& str, const std::string& ending)
{
  if (str.length() >= ending.length())
    return (
        0 ==
        str.compare(str.length() - ending.length(), ending.length(), ending));
  else
    return false;
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



std::string Utils::decodeBase64(const std::string& b64, size_t max)
{
  const auto eSize = decode64Size(b64.length());
  uint8_t* buffer = new uint8_t[eSize];
  size_t len = Botan::base64_decode(buffer, b64, false);

  if (len <= max)
  {
    std::string str(reinterpret_cast<const char*>(buffer));
    delete[] buffer;
    return str;
  }
  else
  {
    Log::get().warn("Base64 decoded to " + std::to_string(len) +
                    " bytes, expected " + std::to_string(max));
    delete[] buffer;
    return "";
  }
}



std::shared_ptr<Botan::RSA_PrivateKey> Utils::loadKey(
    const std::string& filename)
{
  static Botan::AutoSeeded_RNG rng;

  try
  {
    // attempt reading key as standardized PKCS8 format
    Log::get().notice("Opening HS key... ");

    auto key = Botan::PKCS8::load_key(filename, rng);
    auto rsaKey = dynamic_cast<Botan::RSA_PrivateKey*>(key);
    if (!rsaKey)
      Log::get().error("The loaded key is not a RSA key!");

    Log::get().notice("Read PKCS8-formatted RSA key.");
    return std::make_shared<Botan::RSA_PrivateKey>(*rsaKey);
  }
  catch (const Botan::Decoding_Error&)
  {
    Log::get().notice("Read OpenSSL-formatted RSA key.");
    return Utils::loadOpenSSLRSA(filename);
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
std::shared_ptr<Botan::RSA_PrivateKey> Utils::loadOpenSSLRSA(
    const std::string& filename)
{
  static Botan::AutoSeeded_RNG rng;
  Botan::DataSource_Stream in(filename);
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
