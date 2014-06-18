/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP IPSec headers
 */

#ifndef ODP_IPSEC_H_
#define ODP_IPSEC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_std_types.h>
#include <odp_byteorder.h>
#include <odp_align.h>
#include <odp_debug.h>

#define ODP_ESPHDR_LEN      8    /**< IPSec ESP header length */
#define ODP_ESPTRL_LEN      2    /**< IPSec ESP trailer length */
#define ODP_AHHDR_LEN      12    /**< IPSec AH header length */

/**
 * IPSec ESP header
 */
typedef struct ODP_PACKED {
	uint32be_t spi;      /**< Security Parameter Index */
	uint32be_t seq_no;   /**< Sequence Number */
	uint8_t    iv[0];    /**< Initialization vector */
} odp_esphdr_t;

/** @internal Compile time assert */
ODP_ASSERT(sizeof(odp_esphdr_t) == ODP_ESPHDR_LEN, ODP_ESPHDR_T__SIZE_ERROR);

/**
 * IPSec ESP trailer
 */
typedef struct ODP_PACKED {
	uint8_t pad_len;      /**< Padding length (0-255) */
	uint8_t next_header;  /**< Next header protocol */
	uint8_t icv[0];       /**< Integrity Check Value (optional) */
} odp_esptrl_t;

/** @internal Compile time assert */
ODP_ASSERT(sizeof(odp_esptrl_t) == ODP_ESPTRL_LEN, ODP_ESPTRL_T__SIZE_ERROR);

/**
 * IPSec AH header
 */
typedef struct ODP_PACKED {
	uint8_t    next_header;  /**< Next header protocol */
	uint8_t    ah_len;       /**< AH header length */
	uint16be_t pad;          /**< Padding (must be 0) */
	uint32be_t spi;          /**< Security Parameter Index */
	uint32be_t seq_no;       /**< Sequence Number */
	uint8_t    icv[0];       /**< Integrity Check Value */
} odp_ahhdr_t;

/** @internal Compile time assert */
ODP_ASSERT(sizeof(odp_ahhdr_t) == ODP_AHHDR_LEN, ODP_AHHDR_T__SIZE_ERROR);

#ifdef __cplusplus
}
#endif

#endif
