/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP IP header
 */

#ifndef ODP_IP_H_
#define ODP_IP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_align.h>
#include <odp_debug.h>
#include <odp_byteorder.h>
#include <helper/odp_chksum.h>

#include <string.h>

#define ODP_IPV4             4  /**< IP version 4 */
#define ODP_IPV4HDR_LEN     20  /**< Min length of IP header (no options) */
#define ODP_IPV4HDR_IHL_MIN  5  /**< Minimum IHL value*/

/** @internal Returns IPv4 version */
#define ODP_IPV4HDR_VER(ver_ihl) (((ver_ihl) & 0xf0) >> 4)

/** @internal Returns IPv4 header length */
#define ODP_IPV4HDR_IHL(ver_ihl) ((ver_ihl) & 0x0f)

/** @internal Returns IPv4 Don't fragment */
#define ODP_IPV4HDR_FLAGS_DONT_FRAG(frag_offset)  ((frag_offset) & 0x4000)

/** @internal Returns IPv4 more fragments */
#define ODP_IPV4HDR_FLAGS_MORE_FRAGS(frag_offset)  ((frag_offset) & 0x2000)

/** @internal Returns IPv4 fragment offset */
#define ODP_IPV4HDR_FRAG_OFFSET(frag_offset) ((frag_offset) & 0x1fff)

/** @internal Returns true if IPv4 packet is a fragment */
#define ODP_IPV4HDR_IS_FRAGMENT(frag_offset) ((frag_offset) & 0x3fff)

/** IPv4 header */
typedef struct ODP_PACKED {
	uint8_t    ver_ihl;     /**< Version / Header length */
	uint8_t    tos;         /**< Type of service */
	uint16be_t tot_len;     /**< Total length */
	uint16be_t id;          /**< ID */
	uint16be_t frag_offset; /**< Fragmentation offset */
	uint8_t    ttl;         /**< Time to live */
	uint8_t    proto;       /**< Protocol */
	uint16be_t chksum;      /**< Checksum */
	uint32be_t src_addr;    /**< Source address */
	uint32be_t dst_addr;    /**< Destination address */
} odp_ipv4hdr_t;

/** @internal Compile time assert */
ODP_ASSERT(sizeof(odp_ipv4hdr_t) == ODP_IPV4HDR_LEN, ODP_IPV4HDR_T__SIZE_ERROR);

/**
 * Check if IPv4 checksum is valid
 *
 * @param pkt  ODP packet
 *
 * @return 1 if checksum is valid, otherwise 0
 */
static inline int odp_ipv4_csum_valid(odp_packet_t pkt)
{
	uint16be_t res = 0;
	uint16_t *w;
	int nleft = sizeof(odp_ipv4hdr_t);
	odp_ipv4hdr_t ip;
	uint16be_t chksum;

	if (!odp_packet_l3_offset(pkt))
		return 0;

	memcpy(&ip, odp_packet_l3(pkt), sizeof(odp_ipv4hdr_t));
	w = (uint16_t *)(void *)&ip;
	chksum = ip.chksum;
	ip.chksum = 0x0;

	res = odp_chksum(w, nleft);
	return (res == chksum) ? 1 : 0;
}

/**
 * Calculate and fill in IPv4 checksum
 *
 * @note when using this api to populate data destined for the wire
 * odp_cpu_to_be_16() can be used to remove sparse warnings
 *
 * @param pkt  ODP packet
 *
 * @return IPv4 checksum in host cpu order, or 0 on failure
 */
static inline uint16_t odp_ipv4_csum_update(odp_packet_t pkt)
{
	uint16_t res = 0;
	uint16_t *w;
	odp_ipv4hdr_t *ip;
	int nleft = sizeof(odp_ipv4hdr_t);

	if (!odp_packet_l3_offset(pkt))
		return 0;

	ip = (odp_ipv4hdr_t *)odp_packet_l3(pkt);
	w = (uint16_t *)(void *)ip;
	res = odp_chksum(w, nleft);
	ip->chksum = odp_cpu_to_be_16(res);
	return res;
}

/** IPv6 version */
#define ODP_IPV6 6

/** IPv6 header length */
#define ODP_IPV6HDR_LEN 40

/**
 * IPv6 header
 */
typedef struct ODP_PACKED {
	uint32be_t ver_tc_flow;  /**< Version / Traffic class / Flow label */
	uint16be_t payload_len;  /**< Payload length */
	uint8_t    next_hdr;     /**< Next header */
	uint8_t    hop_limit;    /**< Hop limit */
	uint8_t    src_addr[16]; /**< Source address */
	uint8_t    dst_addr[16]; /**< Destination address */
} odp_ipv6hdr_t;

/** @internal Compile time assert */
ODP_ASSERT(sizeof(odp_ipv6hdr_t) == ODP_IPV6HDR_LEN, ODP_IPV6HDR_T__SIZE_ERROR);

/** @name
 * IP protocol values (IPv4:'proto' or IPv6:'next_hdr')
 * @{*/
#define ODP_IPPROTO_ICMP 0x01 /**< Internet Control Message Protocol (1) */
#define ODP_IPPROTO_TCP  0x06 /**< Transmission Control Protocol (6) */
#define ODP_IPPROTO_UDP  0x11 /**< User Datagram Protocol (17) */
#define ODP_IPPROTO_SCTP 0x84 /**< Stream Control Transmission Protocol (132) */
#define ODP_IPPROTO_FRAG 0x2C /**< Fragment (44) */
#define ODP_IPPROTO_AH   0x33 /**< Authentication Header (51) */
#define ODP_IPPROTO_ESP  0x32 /**< Encapsulating Security Payload (50) */
/**@}*/

#ifdef __cplusplus
}
#endif

#endif
