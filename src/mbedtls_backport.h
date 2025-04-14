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

#ifndef MBEDTLSBACKPORT_H_INCLUDE
#define MBEDTLSBACKPORT_H_INCLUDED

#include <mbedtls/version.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

int patched_mbedtls_ecp_point_read_binary(const mbedtls_ecp_group *grp,
                                  mbedtls_ecp_point *pt,
                                  const unsigned char *buf, size_t ilen);

#endif
