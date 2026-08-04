/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

/**
  @file crypt_register_hash.c
  Register a HASH, Tom St Denis
*/

/**
   Register a hash with the descriptor table
   @param hash   The hash you wish to register
   @return value >= 0 if successfully added (or already present), -1 if unsuccessful
*/
int register_hash(const struct ltc_hash_descriptor *hash)
{
   int x, blank = -1;

   LTC_ARGCHK(hash != NULL);

   if (hash->name == NULL)
      return -1;

   /* is it already registered? */
   LTC_MUTEX_LOCK(&ltc_hash_mutex);
   for (x = 0; x < TAB_SIZE; x++) {
       if (XMEMCMP(&hash_descriptor[x], hash, sizeof(struct ltc_hash_descriptor)) == 0) {
          LTC_MUTEX_UNLOCK(&ltc_hash_mutex);
          return x;
       }
       if (hash_descriptor[x].name == NULL && blank == -1) {
          blank = x;
       }
   }

   /* fill in blank spot */
   if (blank != -1) {
       XMEMCPY(&hash_descriptor[blank], hash, sizeof(struct ltc_hash_descriptor));
   }

   /* no spot */
   LTC_MUTEX_UNLOCK(&ltc_hash_mutex);
   return blank;
}
