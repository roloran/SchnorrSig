/**
* Backport of mbedtls_ecp_point_read_binary and associated functions from
* mbedtls 3.6.1. The ESP32 Arduino library (version 2.0.X) contains an older
* version of mbedtls without this function.
* This file includes this function with the prefix patched_ and the necessary
* dependencies.
* Functions for multiplication, addition, and subtraction have been changed
* to those available in mbedtls for ESP32 Arduino 2.0.X.
* If you are using the ESP32 Arduino library version 3.1.X or higher, this is
* not needed, as this version includes a mbedtls version with direct support
* for mbedtls_ecp_point_read_binary.
*/

#include "mbedtls_backport.h"
#if MBEDTLS_VERSION_MAJOR == 2

/*
 *  Elliptic curves over GF(p): generic functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * Computes the right-hand side of the Short Weierstrass equation
 * RHS = X^3 + A X + B
 */
static int ecp_sw_rhs(const mbedtls_ecp_group *grp,
                      mbedtls_mpi *rhs,
                      const mbedtls_mpi *X)
{
    int ret;

    /* Compute X^3 + A X + B as X (X^2 + A) + B */
    //MPI_ECP_SQR(rhs, X);
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(rhs, X, X));
    
    /* Special case for A = -3 */
    if (mbedtls_ecp_group_a_is_minus_3(grp)) {
        //MPI_ECP_SUB_INT(rhs, rhs, 3);
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(rhs, rhs, 3));
    } else {
        //MPI_ECP_ADD(rhs, rhs, &grp->A);
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(rhs, rhs, &grp->A));
    }

    //MPI_ECP_MUL(rhs, rhs, X);
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(rhs, rhs, X));
    //MPI_ECP_ADD(rhs, rhs, &grp->B);
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(rhs, rhs, &grp->B));

cleanup:
    return ret;
}

/*
 * Derive Y from X and a parity bit
 */
static int mbedtls_ecp_sw_derive_y(const mbedtls_ecp_group *grp,
                                   const mbedtls_mpi *X,
                                   mbedtls_mpi *Y,
                                   int parity_bit)
{
    /* w = y^2 = x^3 + ax + b
     * y = sqrt(w) = w^((p+1)/4) mod p   (for prime p where p = 3 mod 4)
     *
     * Note: this method for extracting square root does not validate that w
     * was indeed a square so this function will return garbage in Y if X
     * does not correspond to a point on the curve.
     */

    /* Check prerequisite p = 3 mod 4 */
    if (mbedtls_mpi_get_bit(&grp->P, 0) != 1 ||
        mbedtls_mpi_get_bit(&grp->P, 1) != 1) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    int ret;
    mbedtls_mpi exp;
    mbedtls_mpi_init(&exp);

    /* use Y to store intermediate result, actually w above */
    MBEDTLS_MPI_CHK(ecp_sw_rhs(grp, Y, X));

    /* w = y^2 */ /* Y contains y^2 intermediate result */
    /* exp = ((p+1)/4) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(&exp, &grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&exp, 2));
    /* sqrt(w) = w^((p+1)/4) mod p   (for prime p where p = 3 mod 4) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(Y, Y /*y^2*/, &exp, &grp->P, NULL));

    /* check parity bit match or else invert Y */
    /* This quick inversion implementation is valid because Y != 0 for all
     * Short Weierstrass curves supported by mbedtls, as each supported curve
     * has an order that is a large prime, so each supported curve does not
     * have any point of order 2, and a point with Y == 0 would be of order 2 */
    if (mbedtls_mpi_get_bit(Y, 0) != parity_bit) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(Y, &grp->P, Y));
    }

cleanup:

    mbedtls_mpi_free(&exp);
    return ret;
}


/*
 * Import a point from unsigned binary data (SEC1 2.3.4 and RFC7748)
 */
int patched_mbedtls_ecp_point_read_binary(const mbedtls_ecp_group *grp,
                                  mbedtls_ecp_point *pt,
                                  const unsigned char *buf, size_t ilen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;
    if (ilen < 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    plen = mbedtls_mpi_size(&grp->P);

#if defined(MBEDTLS_ECP_MONTGOMERY_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        if (plen != ilen) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary_le(&pt->X, buf, plen));
        mbedtls_mpi_free(&pt->Y);

        if (grp->id == MBEDTLS_ECP_DP_CURVE25519) {
            /* Set most significant bit to 0 as prescribed in RFC7748 §5 */
            MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&pt->X, plen * 8 - 1, 0));
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 1));
    }
#endif
#if defined(MBEDTLS_ECP_SHORT_WEIERSTRASS_ENABLED)
    if (mbedtls_ecp_get_type(grp) == MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS) {
        if (buf[0] == 0x00) {
            if (ilen == 1) {
                return mbedtls_ecp_set_zero(pt);
            } else {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
        }

        if (ilen < 1 + plen) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }

        MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&pt->X, buf + 1, plen));
        MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&pt->Z, 1));

        if (buf[0] == 0x04) {
            /* format == MBEDTLS_ECP_PF_UNCOMPRESSED */
            if (ilen != 1 + plen * 2) {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            return mbedtls_mpi_read_binary(&pt->Y, buf + 1 + plen, plen);
        } else if (buf[0] == 0x02 || buf[0] == 0x03) {
            /* format == MBEDTLS_ECP_PF_COMPRESSED */
            if (ilen != 1 + plen) {
                return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
            }
            return mbedtls_ecp_sw_derive_y(grp, &pt->X, &pt->Y,
                                           (buf[0] & 1));
        } else {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }
#endif

cleanup:
    return ret;
}
#endif
