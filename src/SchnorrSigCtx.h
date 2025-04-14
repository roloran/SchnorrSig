#ifndef SchnorrSigCtx_h
#define SchnorrSigCtx_h

//#define USE_SECP192K1

#ifdef __cplusplus
extern "C" {
#endif
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#ifdef __cplusplus
}
#endif

#ifdef USE_SECP192K1
    #define SCHNORR_EC MBEDTLS_ECP_DP_SECP192K1
    #define SCHNORR_MPI_LEN 24
#else
    #define SCHNORR_EC MBEDTLS_ECP_DP_SECP256K1
    #define SCHNORR_MPI_LEN 32
#endif

class SchnorrSigCtx
{
        public:
                struct signature {
                        size_t sig_len = 0;
                        size_t point_len = 0;
                        uint8_t sig[SCHNORR_MPI_LEN];
                        uint8_t point[SCHNORR_MPI_LEN+1]; //33bytes compressed, 65bytes uncompressed
                };
                
                struct pubkey {
                    mbedtls_ecp_point A;
                };
                
                struct privkey {
                    pubkey* pub;
                    mbedtls_mpi a;
                };
                
                struct signature_mbedtls {
                        mbedtls_ecp_point R;
                        mbedtls_mpi s;
                };

                mbedtls_entropy_context entropy_;
                mbedtls_ctr_drbg_context ctr_drbg_;
                mbedtls_ecp_group group;

                static pubkey *init_pubkey();
                static privkey *init_privkey();
                static void free_pubkey(pubkey *pub);
                static void free_privkey(privkey *priv);
                
                SchnorrSigCtx();
                int init(uint8_t *seed, size_t seed_len);
                uint8_t is_initialized();
                privkey *gen_keypair();
                int export_private_key(privkey *priv, char (&keyout)[128], size_t *key_size);
                int export_public_key(pubkey *pub, uint8_t (&keyout)[256], size_t *key_size);
                int hash(const unsigned char* msg, const size_t len,
                         const mbedtls_ecp_point* R, mbedtls_mpi* out);
        private:
                uint8_t initialized_ = 0;
                int initialize_sys_random(uint8_t *seed, size_t seed_len);
};

#endif
