#include "SchnorrSigSign.h"
#include "SchnorrSigCtx.h"

/**
 * SchnorrSigSign() - Create a SSS object
 *
 * This object needs to be initialized before use.
 *
 * Return: SchnorrSigSign object
 */
SchnorrSigSign::SchnorrSigSign()
{
}

/**
 * ~SchnorrSigSign() - Delete a SSS object
 */
SchnorrSigSign::~SchnorrSigSign()
{
}

/**
 * init() - Initialize a SchnorrSigSign object
 * @ssc: The context to use for this SSC object
 * @public_key: The private key messages should be signed with as hexadecimal string
 *
 * Return: 0 on success
 *
 */
int SchnorrSigSign::init(SchnorrSigCtx *ssc, const char *private_key)
{
        if(initialized_ != 0)
                return -3;

        // Save pointer to context
        if(ssc->is_initialized() == 1)
                ssc_ = ssc;
        else
                return -2;

        // Load private key
        priv_ = ssc->gen_keypair();
        if(priv_ == NULL)
                return -1;
                
                
        mbedtls_mpi_read_string(&priv_->a, 16, private_key);
        if(mbedtls_ecp_check_privkey(&ssc->group, &priv_->a) != 0)
                return -1;

        initialized_= 1;
        return 0;
}

/**
 * init() - Initialize a SchnorrSigSign object
 * @ssc: The context to use for this SSC object
 * @key: The private key messages should be signed with
 *
 * Return: 0 on success
 *
 */
int SchnorrSigSign::init(SchnorrSigCtx *ssc, SchnorrSigCtx::privkey *priv)
{
        if(initialized_ != 0)
                return -3;

        // Save pointer to context
        if(ssc->is_initialized() == 1)
                ssc_ = ssc;
        else
                return -2;

        // Load private key
        if(priv == NULL)
                return -1;

        priv_ = priv;

        initialized_= 1;
        return 0;
}

/**
 * sign() - Sign the message using the private key of the SSS object
 * @msg: The message
 * @msg_len: The message's length
 * @sig: The SSS object to use
 *
 * Return: 0 on success, <0 otherwise
 */
int SchnorrSigSign::sign(const unsigned char *msg, int msg_len, struct SchnorrSigCtx::signature *sig)
{
        if(initialized_ == 0)
                return -2;

        SchnorrSigCtx::signature_mbedtls *s_sig;
        mbedtls_mpi k;
        mbedtls_mpi BNh;
        mbedtls_mpi s;
        int error = 1;
        int ret;
   
        s_sig = (SchnorrSigCtx::signature_mbedtls*) malloc(sizeof(SchnorrSigCtx::signature_mbedtls));
        if(s_sig == NULL) {
            goto cleanup;
        }
        mbedtls_ecp_point_init(&s_sig->R);
        mbedtls_mpi_init(&s_sig->s);
    
        mbedtls_mpi_init(&k);
    
        if(mbedtls_mpi_fill_random(&k, SCHNORR_MPI_LEN, mbedtls_ctr_drbg_random, &ssc_->ctr_drbg_) != 0) {
            goto cleanup;
        }
    
        if(mbedtls_ecp_mul(&ssc_->group, &s_sig->R, &k, &ssc_->group.G, mbedtls_ctr_drbg_random, &ssc_->ctr_drbg_) != 0) {
            goto cleanup;
        }
    
        mbedtls_mpi_init(&BNh);
    
        if(ssc_->hash(msg, msg_len, &s_sig->R, &BNh) != 0) {
            goto cleanup;
        }
    
        mbedtls_mpi_init(&s);
    
        if(mbedtls_mpi_mul_mpi(&s, &BNh, &priv_->a) != 0){
            goto cleanup;
        }
        if(mbedtls_mpi_mod_mpi(&s, &s, &ssc_->group.N) != 0){
            goto cleanup;
        }
    
        if(mbedtls_mpi_sub_mpi(&s, &k, &s) != 0){
            goto cleanup;
        }
        if(mbedtls_mpi_mod_mpi(&s, &s, &ssc_->group.N) != 0) {
            goto cleanup;
        }
    
        mbedtls_mpi_copy(&s_sig->s, &s);
    
        ret = mbedtls_ecp_point_write_binary(&ssc_->group,
                                             &s_sig->R,
                                             MBEDTLS_ECP_PF_COMPRESSED,
                                             &sig->point_len,
                                             sig->point,
                                             sizeof(sig->point));
        if(ret != 0) {
                goto cleanup;
        }

        if(mbedtls_mpi_write_binary(&s_sig->s, sig->sig, SCHNORR_MPI_LEN) != 0) {
                goto cleanup;
        }
        sig->sig_len = mbedtls_mpi_size(&s_sig->s);

        error = 0;
        cleanup:
        mbedtls_mpi_free(&BNh);
        mbedtls_mpi_free(&k);
        mbedtls_mpi_free(&s);
        if(s_sig != NULL) {
                mbedtls_ecp_point_free(&s_sig->R);
                mbedtls_mpi_free(&s_sig->s);
                free(s_sig);
        }
        if(error) {
                return -1;
        }
        return 0;
}
