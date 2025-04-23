#include <string.h>
#include "SchnorrSigVerify.h"
#include "SchnorrSigCtx.h"

/**
 * SchnorrSigVerify() - Create a SSV object
 *
 * This object needs to be initialized before use.
 *
 * Return: SchnorrSigVerify object
 */
SchnorrSigVerify::SchnorrSigVerify()
{
}

/**
 * ~SchnorrSigVerify() - Delete a SSV object
 */
SchnorrSigVerify::~SchnorrSigVerify()
{
}

/**
 * init() - Initialize the SchnorrSigVerify object
 * @ssc: The context to use for the SSV object
 * @public_key: The public key messages should be verified with as hexadecimal string
 *
 * Return: 0 on success
 *
 */
int SchnorrSigVerify::init(SchnorrSigCtx *ssc, const char *public_key)
{
        int ret = 0;
        uint8_t pubkey_bin[SCHNORR_MPI_LEN+1];
        if(initialized_ != 0)
                return -3;

        // Save pointer to context
        if(ssc->is_initialized() == 1)
                ssc_ = ssc;
        else
                return -2;

        // Load public key
        pub_ = ssc_->init_pubkey();
        for(int i = 0; i < sizeof(pubkey_bin); i++) {
            sscanf(public_key+(2*i), "%2hhx", &pubkey_bin[i]);
        }
        #if MBEDTLS_VERSION_MAJOR == 2
        ret = patched_mbedtls_ecp_point_read_binary(&ssc_->group, &pub_->A, pubkey_bin, sizeof(pubkey_bin));
        #else
        ret = mbedtls_ecp_point_read_binary(&ssc_->group, &pub_->A, pubkey_bin, sizeof(pubkey_bin));
        #endif
        if (ret != 0) {
            return ret;
        }
        mbedtls_ecp_check_pubkey(&ssc_->group, &pub_->A);

        initialized_ = 1;
        return 0;
}

/**
 * init() - Initialize the SchnorrSigVerify object
 * @ssc: The context to use for the SSV object
 * @public_key: The public key messages
 *
 * Return: 0 on success
 *
 */
int SchnorrSigVerify::init(SchnorrSigCtx *ssc, SchnorrSigCtx::pubkey *pub)
{
        if(initialized_ != 0)
                return -3;

        // Save pointer to context
        if(ssc->is_initialized() == 1)
                ssc_ = ssc;
        else
                return -2;

        if(pub == NULL)
                return -1;
        pub_ = pub;

        initialized_ = 1;
        return 0;
}

/**
 * verify() - Verify a signature using the public key of the SSV object
 * @msg: The message, for which the signature has been created
 * @msg_len: The message's length
 * @sig: The signature
 *
 * Return: 0 on success, <0 otherwise
 */
int SchnorrSigVerify::verify(const unsigned char *msg, int msg_len, struct SchnorrSigCtx::signature *sig)
{
        if(initialized_ == 0)
                return -2;

        int ret = -1;
        SchnorrSigCtx::signature_mbedtls s_sig;
        mbedtls_mpi BNh;
        mbedtls_ecp_point R;
 
        // Load data from signature struct
        mbedtls_mpi_init(&s_sig.s);
        mbedtls_ecp_point_init(&s_sig.R);
        mbedtls_mpi_read_binary(&s_sig.s, sig->sig, sig->sig_len);
        #if MBEDTLS_VERSION_MAJOR == 2
        patched_mbedtls_ecp_point_read_binary(&ssc_->group, &s_sig.R, sig->point, sig->point_len);
        #else
        mbedtls_ecp_point_read_binary(&ssc_->group, &s_sig.R, sig->point, sig->point_len);
        #endif
       
        if(mbedtls_mpi_cmp_mpi(&s_sig.s, &ssc_->group.N) != -1){
                goto cleanup;
        }
        
        mbedtls_mpi_init(&BNh);
        
        if(ssc_->hash(msg, msg_len, &s_sig.R, &BNh) != 0) {
                goto cleanup;
        }
        
        mbedtls_ecp_point_init(&R);
        
        if(mbedtls_ecp_muladd(&ssc_->group, &R, &s_sig.s, &ssc_->group.G, &BNh, &pub_->A) != 0) {
                goto cleanup;
        }
        
        if(mbedtls_ecp_is_zero(&R) == 1) {
                goto cleanup;
        }
        
        ret = mbedtls_ecp_point_cmp(&R, &s_sig.R);
        
        cleanup:
        mbedtls_ecp_point_free(&s_sig.R);
        mbedtls_mpi_free(&s_sig.s);
        mbedtls_ecp_point_free(&R);
        mbedtls_mpi_free(&BNh);
        
        return ret;
}

/**
* load() - Load signature from hex encoded representation
* @signature_string: Hex encoded point followed by hex encoded signature delimited by ':'
* @sig: The signature, where the encoded data is stored
*
* Return: 0 on success, <0 otherwise
*/
int SchnorrSigVerify::load(const char* signature_string, SchnorrSigCtx::signature *sig)
{
    if(strlen(signature_string) != 64+66+1) {
      return -1;
    }
    const char* p = signature_string;
    const char* sep = strchr(signature_string, ':');
    if(sep == NULL) {
          return -2;
    }
    
    uint8_t buf[128];
    for(int i = 0; i < 66; i++) {
        sscanf(p+(2*i), "%2hhx", &buf[i]);
    }
    memcpy(&sig->point, buf, 33);
    sig->point_len = 33;
    
    
    for(int i = 0; i < 64; i++) {
        sscanf(sep+1+(2*i), "%2hhx", &buf[i]);
    }
    memcpy(&sig->sig, buf, 32);
    sig->sig_len = 32;
    
    return 0;
}
