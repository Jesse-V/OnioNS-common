
#include "CreateR.hpp"
#include "../../Common.hpp"
#include <botan/base64.h>


CreateR::CreateR(Botan::RSA_PrivateKey* key,
                 const std::string& primaryName,
                 const std::string& contact)
    : Record(key)
{
  type_ = "Create";
  setName(primaryName);
  setContact(contact);
}



CreateR::CreateR(const std::string& contact,
                 const std::string& name,
                 const NameList& subdomains,
                 const std::string& nonce,
                 const std::string& sig,
                 Botan::RSA_PublicKey* pubKey)
    : Record(pubKey)
{
  type_ = "Create";
  setContact(contact);
  setName(name);
  setSubdomains(subdomains);

  Botan::base64_decode(nonce_.data(), nonce, false);
  Botan::base64_decode(signature_.data(), sig, false);
}
