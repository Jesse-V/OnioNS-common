
#include <botan/sha2_64.h>


struct ed25519_hash_context
{
  Botan::SHA_512* sha512;
};



void ed25519_hash_init(ed25519_hash_context* ctx)
{
  ctx->sha512 = new Botan::SHA_512();
}



void ed25519_hash_update(ed25519_hash_context* ctx,
                         const uint8_t* in,
                         size_t inlen)
{
  ctx->sha512->update(in, inlen);
}



void ed25519_hash_final(ed25519_hash_context* ctx, uint8_t* hash)
{
  ctx->sha512->final(hash);
  delete ctx->sha512;
}



void ed25519_hash(uint8_t* hash, const uint8_t* in, size_t inlen)
{
  Botan::SHA_512 sha512;
  sha512.update(in, inlen);
  sha512.final(hash);
}
