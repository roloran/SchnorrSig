#ifndef SchnorrSigSign_h
#define SchnorrSigSign_h

#include "SchnorrSigCtx.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "mbedtls_backport.h"
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#ifdef __cplusplus
}
#endif

class SchnorrSigSign
{
        public:
                SchnorrSigSign();
                ~SchnorrSigSign();
                int init(SchnorrSigCtx *sig_obj, const char *private_key);
                int init(SchnorrSigCtx *sig_obj, SchnorrSigCtx::privkey *priv);
                int sign(const unsigned char *msg, int msg_len, struct SchnorrSigCtx::signature *sig);
        private:
                uint8_t initialized_ = 0;
                SchnorrSigCtx::privkey *priv_;
                SchnorrSigCtx *ssc_;
};

#endif
