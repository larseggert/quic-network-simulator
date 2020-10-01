#ifndef OPENSSL_HELPER_H
#define OPENSSL_HELPER_H

#include <openssl/evp.h>

extern "C" {

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len, unsigned char *tag,
                unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext);
}

#endif // OPENSSL_HELPER_H
