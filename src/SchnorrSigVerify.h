#ifndef SchnorrSigVerify_h
#define SchnorrSigVerify_h

#include "SchnorrSigCtx.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <mbedtls/version.h>
#if MBEDTLS_VERSION_MAJOR == 2
#include "mbedtls_backport.h"
#endif

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#ifdef __cplusplus
}
#endif

class SchnorrSigVerify
{
        public:
                SchnorrSigVerify();
                ~SchnorrSigVerify();
                int init(SchnorrSigCtx *ssc, const char *public_key);
                int init(SchnorrSigCtx *ssc, SchnorrSigCtx::pubkey *pub);
                int verify(const unsigned char *msg, int msg_len, struct SchnorrSigCtx::signature *sig);
                int load(const char* signature_string, SchnorrSigCtx::signature *sig);
        private:
                uint8_t initialized_ = 0;
                SchnorrSigCtx::pubkey *pub_;
                SchnorrSigCtx *ssc_;
};

#endif
