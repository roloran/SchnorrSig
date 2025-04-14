#include "SchnorrSigCtx.h"
#include <cstdio>

/**
 * SchnorrSigCtx() - Create a SSC object
 *
 * This object needs to be initialized before use.
 *
 * Return: SchnorrSigCtx object
 */
SchnorrSigCtx::SchnorrSigCtx()
{
}

/**
 * init() - Initialize the SchnorrSigCtx object
 *
 * Return: 0 on success, -1 otherwise
 */
int SchnorrSigCtx::init(uint8_t *seed, size_t seed_len)
{
        // Initialize the random number generator
        if(initialize_sys_random(seed, seed_len) != 0) {
                return -1;
        }

        // Initialize the group
        mbedtls_ecp_group_init(&group);
        if(mbedtls_ecp_group_load(&group, SCHNORR_EC) != 0) {
                return -2;
        }
        
        initialized_ = 1;
        return 0;
}

/**
 * initialize_sys_random() - Initialize the random number generator using hardware entropy
 *
 * Return: 0 on success, -1 otherwise
 */
int SchnorrSigCtx::initialize_sys_random(uint8_t *seed, size_t seed_len)
{
        mbedtls_entropy_init(&entropy_);
        mbedtls_ctr_drbg_init(&ctr_drbg_);
        if(mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_, seed, seed_len) != 0) {
                return -1;
        }
        return 0;
}

/**
* is_initialized() - Get the initialization status of the object
*
* Return: 1 if the object has been initialized, 0 otherwise
*/
uint8_t SchnorrSigCtx::is_initialized()
{
        return initialized_;
}


SchnorrSigCtx::pubkey *SchnorrSigCtx::init_pubkey()
{
        pubkey *pub = (pubkey*) malloc(sizeof(pubkey));
        if(pub == NULL) {
                return NULL;
        }
            
        mbedtls_ecp_point_init(&pub->A);
           
        return pub;
}

SchnorrSigCtx::privkey *SchnorrSigCtx::init_privkey()
{
        privkey *priv = (privkey*) malloc(sizeof(privkey));
        if(priv == NULL) {
                return NULL;
        }
        mbedtls_mpi_init(&priv->a);
                 
        priv->pub = init_pubkey();
        if(priv->pub == NULL) {
                free_privkey(priv);
                return NULL;
        }
        
        return priv;
}


/**
* gen_keypair() - Generate a new Schnorr keypair
*
* Allocates memory for and generates a new Schnorr keypair.
*
* Return: Pointer to new Schnorr keypair or NULL on error
*/
SchnorrSigCtx::privkey *SchnorrSigCtx::gen_keypair()
{
        int ret = 0;
        int error = 1;
        if(initialized_ != 1)
                return NULL;

        privkey *priv = init_privkey();
        if(priv == NULL) {
                goto cleanup;
        }
       
        if(mbedtls_mpi_fill_random(&priv->a, SCHNORR_MPI_LEN, mbedtls_ctr_drbg_random, &ctr_drbg_) != 0) {
                goto cleanup;
        }
            
        if(mbedtls_mpi_cmp_int(&priv->a, 0) == 0) {
                goto cleanup;
        }
            
        if(mbedtls_ecp_mul(&group, &priv->pub->A, &priv->a, &(group.G), mbedtls_ctr_drbg_random, &ctr_drbg_) != 0){
                goto cleanup;
        }
            
        error = 0;
            
        cleanup:
        if(error) {
                free_privkey(priv);
                return NULL;
        }
            
        return priv;
}


/**
* free_pubkey() - Free the memory allocated by the keypair
* @pub: The public key to free
*/
void SchnorrSigCtx::free_pubkey(pubkey *pub)
{
      if(pub != NULL) {
              mbedtls_ecp_point_free(&pub->A);
              free(pub);
      }
}

/**
* free_privkey() - Free the memory allocated by the keypair
* @priv: The private key to free
*/
void SchnorrSigCtx::free_privkey(privkey *priv)
{
        if(priv != NULL) {
                if(priv->pub != NULL) {
                        free_pubkey(priv->pub);
                }
                mbedtls_mpi_free(&priv->a);
                free(priv);
        }
}

/**
* export_private_key() - Export the private key as hexadecimal *char* array
* @keypair: Which keypair to export the private key from
* @keyout: The array to store the exported key in
* @key_size: The actual length of the exported key including the \0 terminator
*
* Return: 0 on success
*/
int SchnorrSigCtx::export_private_key(privkey *priv, char (&keyout)[128], size_t *key_size)
{
        return mbedtls_mpi_write_string(&priv->a, 16, keyout, 128, key_size);
}

/**
* export_public_key() - Export the public key as *byte* array
* @keypair: Which keypair to export the public key from
* @keyout: The array to store the exported key in
* @key_size: The actual length of the exported key
*
* Return: 0 on success
*/
int SchnorrSigCtx::export_public_key(pubkey *pub, uint8_t (&keyout)[256], size_t *key_size)
{
        return mbedtls_ecp_point_write_binary(&group, &pub->A, MBEDTLS_ECP_PF_COMPRESSED, key_size, keyout, 256);
}


int SchnorrSigCtx::hash(const unsigned char* msg, const size_t len,
                       const mbedtls_ecp_point* R, mbedtls_mpi* out) {
    int ret = -1;
    mbedtls_sha256_context sha_ctx;
    unsigned char hash[32];
    unsigned char point_bytes[SCHNORR_MPI_LEN+1];
    size_t point_len;
    ret = mbedtls_ecp_point_write_binary(&group, R, MBEDTLS_ECP_PF_COMPRESSED, &point_len, point_bytes, SCHNORR_MPI_LEN+1);
    if(ret != 0 || point_len < SCHNORR_MPI_LEN+1) {
        return ret;
    }
    
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0); // 0 = SHA-256, 1 = SHA-224
    mbedtls_sha256_update(&sha_ctx, point_bytes, point_len);
    mbedtls_sha256_update(&sha_ctx, msg, len);
    mbedtls_sha256_finish(&sha_ctx, hash);

    if(mbedtls_mpi_read_binary(out, hash, SCHNORR_MPI_LEN) != 0) {
        return ret;
    }

    if(mbedtls_mpi_cmp_int(out, 0) == 0) {
        return ret;
    }

    if(mbedtls_mpi_cmp_mpi(out, &group.N) != -1) {
        return ret;
    }

    return 0;
}
