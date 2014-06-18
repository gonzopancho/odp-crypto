/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_example_ipsec.c  ODP basic packet IO cross connect with IPsec test application
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <odp.h>
#include <odp_align.h>
#include <odp_crypto.h>
#include <helper/odp_linux.h>
#include <helper/odp_packet_helper.h>
#include <helper/odp_eth.h>
#include <helper/odp_ip.h>
#include <helper/odp_icmp.h>
#include <helper/odp_ipsec.h>

#include <stdbool.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define boolean bool
#define TRUE  1
#define FALSE 0

#define MAX_WORKERS            32
#define SHM_PKT_POOL_BUF_COUNT 1024
#define SHM_PKT_POOL_BUF_SIZE  4096
#define SHM_PKT_POOL_SIZE      (SHM_PKT_POOL_BUF_COUNT * SHM_PKT_POOL_BUF_SIZE)

#define SHM_OUT_POOL_BUF_COUNT 1024
#define SHM_OUT_POOL_BUF_SIZE  4096
#define SHM_OUT_POOL_SIZE      (SHM_PKT_POOL_BUF_COUNT * SHM_PKT_POOL_BUF_SIZE)

#define MAX_PKT_BURST          16

#define MAX_DB 32

#define LOOP_DEQ_MULTIPLE     0     /**< enable multi packet dequeue */
#define MAX_LOOPBACK          10

#define SEPARATE_PKT_CTX      1     /**< use separate pool for packet context */

#define STREAM_MAGIC 0xBABE01234567CAFE

/**
 * Mode specified on command line indicating how to exercise API
 */
typedef enum {
	CRYPTO_API_SYNC,              /**< Synchronous mode */
	CRYPTO_API_ASYNC_IN_PLACE,    /**< Asynchronous in place */
	CRYPTO_API_ASYNC_NEW_BUFFER   /**< Asynchronous new buffer */
} crypto_api_mode_e;

/**
 * Temporary hack to get around using odp_schedule, intended
 * for helping with bringing up crypto on Keystone.
 *
 * WARNING: Does not work with linux-generic, I verified
 *          that polling the IO queues does not work with
 *          the other packet IO examples either.  They all
 *          have a "#if 1" to select odp_schedule versus
 *          polling IO queues.
 */
#define POLL_QUEUES 0

#if POLL_QUEUES

#define MAX_POLL_QUEUES       256

static odp_queue_t poll_queues[MAX_POLL_QUEUES];
static int num_polled_queues;

static
odp_queue_t my_odp_queue_create(const char *name,
			      odp_queue_type_t type,
			      odp_queue_param_t *param)
{
	odp_queue_t my_queue;
	odp_queue_type_t my_type = type;

	if (ODP_QUEUE_TYPE_SCHED == type) {
		printf("change %s to POLL\n", name);
		my_type = ODP_QUEUE_TYPE_POLL;
	}

	my_queue = odp_queue_create(name, my_type, param);

	if ((ODP_QUEUE_TYPE_SCHED == type) || (ODP_QUEUE_TYPE_PKTIN == type)) {
		poll_queues[num_polled_queues++] = my_queue;
		printf("Adding %d\n", my_queue);
	}

	return my_queue;
}


static
odp_buffer_t my_odp_schedule(odp_queue_t *from, uint64_t wait)
{
	uint64_t start_cycle, cycle, diff;

	start_cycle = 0;

	while (1) {
		int idx;

		for (idx = 0; idx < num_polled_queues; idx++) {
			odp_buffer_t queue = poll_queues[idx];
			odp_buffer_t buf;

			buf = odp_queue_deq(queue);

			if (ODP_BUFFER_INVALID != buf) {
				*from = queue;
				return buf;
			}
		}

		if (wait == ODP_SCHED_WAIT)
			continue;

		if (wait == ODP_SCHED_NO_WAIT)
			break;

		if (start_cycle == 0) {
			start_cycle = odp_time_get_cycles();
			continue;
		}

		cycle = odp_time_get_cycles();
		diff  = odp_time_diff_cycles(start_cycle, cycle);

		if (wait < diff)
			break;
	}

	*from = ODP_QUEUE_INVALID;
	return ODP_BUFFER_INVALID;
}


#define QUEUE_CREATE(n, t, p) my_odp_queue_create(n, t, p)
#define SCHEDULE(q, w)        my_odp_schedule(q, w)

#else

#define QUEUE_CREATE(n, t, p) odp_queue_create(n, t, p)
#define SCHEDULE(q, w)        odp_schedule(q, w)

#endif

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	int type;		/**< Packet IO type */
	int fanout;		/**< Packet IO fanout */
	crypto_api_mode_e mode;	/**< Crypto API preferred mode */
	odp_buffer_pool_t pool;	/**< Buffer pool for packet IO */
} appl_args_t;

/**
 * Thread specific arguments (currently none, leave as placeholder)
 */
typedef struct {
} thread_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
} args_t;

/**
 * Stream packet header
 */
typedef struct ODP_PACKED stream_pkt_hdr_s {
	uint64be_t magic;    /**< Stream magic value for verification */
	uint8_t    data[0];  /**< Incrementing data stream */
} stream_pkt_hdr_t;

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

/** Global pointer to args */
static args_t *args;

/** Buffer pool for crypto session output packets */
static odp_buffer_pool_t out_pool = ODP_BUFFER_POOL_INVALID;

/** ATOMIC queue for IPsec sequence number assignment */
static odp_queue_t seqnumq;

/** ORDERED queue (eventually) for per packet crypto API completion events */
static odp_queue_t completionq;

/** IPv4 helpers for data length and uint8t pointer */
#define ipv4_data_len(ip) (odp_be_to_cpu_16(ip->tot_len) - sizeof(odp_ipv4hdr_t))
#define ipv4_data_p(ip) ((uint8_t *)((odp_ipv4hdr_t *)ip + 1))

/** Helper for calculating encode length using data length and block size */
#define ESP_ENCODE_LEN(x, b) ((((x) + (b - 1)) / b) * b)

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ?                 \
			    strrchr((file_name), '/') + 1 : (file_name))

/** Synchronize threads before packet processing begins */
static odp_barrier_t sync_barrier;

/**
 * IP address range (subnet)
 */
typedef struct ip_addr_range_s {
	uint32_t  addr;     /**< IP address */
	uint32_t  mask;     /**< mask, 1 indicates bits are valid */
} ip_addr_range_t;

/**
 * Packet processing states/steps
 */
typedef enum {
	PKT_STATE_INPUT_VERIFY,        /**< Verify IPv4 and ETH */
	PKT_STATE_IPSEC_IN_CLASSIFY,   /**< Initiate input IPsec */
	PKT_STATE_IPSEC_IN_FINISH,     /**< Finish input IPsec */
	PKT_STATE_ROUTE_LOOKUP,        /**< Use DST IP to find output IF */
	PKT_STATE_IPSEC_OUT_CLASSIFY,  /**< Intiate output IPsec */
	PKT_STATE_IPSEC_OUT_SEQ,       /**< Assign IPsec sequence numbers */
	PKT_STATE_IPSEC_OUT_FINISH,    /**< Finish output IPsec */
	PKT_STATE_TRANSMIT,            /**< Send packet to output IF queue */
} pkt_state_e;

/**
 * Packet processing result codes
 */
typedef enum {
	PKT_CONTINUE,    /**< No events posted, keep processing */
	PKT_POSTED,      /**< Event posted, stop processing */
	PKT_DROP,        /**< Reason to drop detected, stop processing */
	PKT_DONE         /**< Finished with packet, stop processing */
} pkt_disposition_e;

/**
 * IPsec key
 */
typedef struct {
	uint8_t  data[32];  /**< Key data */
	uint8_t  length;    /**< Key length */
} ipsec_key_t;

/**
 * IPsec algorithm
 */
typedef struct {
	bool cipher;
	union {
		enum odp_cipher_alg cipher;
		enum odp_auth_alg   auth;
	} u;
} ipsec_alg_t;

/**
 * Per packet IPsec processing context
 */
typedef struct {
	uint8_t  ip_tos;         /**< Saved IP TOS value */
	uint16_t ip_frag_offset; /**< Saved IP flags value */
	uint8_t  ip_ttl;         /**< Saved IP TTL value */
	int      hdr_len;        /**< Length of IPsec headers */
	int      trl_len;        /**< Length of IPsec trailers */
	uint16_t ah_offset;      /**< Offset of AH header from buffer start */
	uint16_t esp_offset;     /**< Offset of ESP header from buffer start */

	/* Output only */
	odp_crypto_op_params_t params;  /**< Parameters for crypto call */
	uint32_t *ah_seq;                    /**< AH sequence number location */
	uint32_t *esp_seq;                   /**< ESP sequence number location */
} ipsec_ctx_t;

/**
 * Per packet processing context
 */
typedef union {
	struct {
		odp_buffer_t buffer;  /**< Buffer for context */
		pkt_state_e  state;   /**< Next processing step */
		ipsec_ctx_t  ipsec;   /**< IPsec specific context */
		odp_queue_t  outq;    /**< transmit queue */
	};
	uint8_t pad[256];             /**< Ensure no overlap with crypto */
} pkt_ctx_t;

#define SHM_CTX_POOL_BUF_SIZE  (sizeof(pkt_ctx_t))
#define SHM_CTX_POOL_BUF_COUNT (SHM_PKT_POOL_BUF_COUNT + SHM_OUT_POOL_BUF_COUNT)
#define SHM_CTX_POOL_SIZE      (SHM_CTX_POOL_BUF_COUNT * SHM_CTX_POOL_BUF_SIZE)

static odp_buffer_pool_t ctx_pool = ODP_BUFFER_POOL_INVALID;

/**
 * Adjust IPv4 length
 *
 * @param ip   Pointer to IPv4 header
 * @param adj  Signed adjustment value
 */
static
void ipv4_adjust_len(odp_ipv4hdr_t *ip, int adj)
{
	ip->tot_len = odp_cpu_to_be_16(odp_be_to_cpu_16(ip->tot_len) + adj);
}

#if SEPARATE_PKT_CTX

/**
 * Get per packet processing context from packet buffer
 *
 * @param pkt  Packet
 *
 * @return pointer to context area
 */
static
pkt_ctx_t *get_pkt_ctx_from_pkt(odp_packet_t pkt)
{
	return (pkt_ctx_t *)odp_packet_get_ctx(pkt);
}

/**
 * Allocate per packet processing context and associate it with
 * packet buffer
 *
 * @param pkt  Packet
 *
 * @return pointer to context area
 */
static
pkt_ctx_t *alloc_pkt_ctx(odp_packet_t pkt)
{
	odp_buffer_t ctx_buf = odp_buffer_alloc(ctx_pool);
	pkt_ctx_t *ctx;

	/* There should always be enough contexts */
	if (odp_unlikely(ODP_BUFFER_INVALID == ctx_buf))
		abort();

	ctx = odp_buffer_addr(ctx_buf);
	memset(ctx, 0, sizeof(*ctx));
	ctx->buffer = ctx_buf;
	odp_packet_set_ctx(pkt, (void *)ctx);

	return ctx;
}

/**
 * Release per packet resources
 *
 * @param ctx  Packet context
 */
static
void free_pkt_ctx(pkt_ctx_t *ctx)
{
	odp_buffer_free(ctx->buffer);
}

#else

/**
 * Get per packet processing context from packet buffer
 *
 * This is a hack for the moment to place it at the end of the
 * buffer.  Note that the crypto library also has a similar hack
 * so we space our packet context 256 bytes from the end to prevent
 * overlap.
 *
 * @param buf  Buffer associated with packet
 *
 * @return pointer to context area
 */
static
pkt_ctx_t *get_pkt_ctx_from_pkt(odp_packet_t pkt)
{
	odp_buffer_t buf = odp_buffer_from_packet(pkt);
	uint8_t   *temp;
	pkt_ctx_t *ctx;

	/*
	 * Setup packet context,
	 */
	temp  = odp_buffer_addr(buf);
	temp += odp_buffer_size(buf);
	temp -= sizeof(*ctx);
	ctx = (pkt_ctx_t *)(void *)temp;
	return ctx;
}

/**
 * Allocate per packet processing context and associate it with
 * packet buffer (in this mode simply get pointer and initialize)
 *
 * @param pkt  Packet
 *
 * @return pointer to context area
 */
static
pkt_ctx_t *alloc_pkt_ctx(odp_packet_t pkt)
{
	pkt_ctx_t *ctx = get_pkt_ctx_from_pkt(pkt);

	memset(ctx, 0, sizeof(*ctx));
	return ctx;
}

/**
 * Release per packet resources
 *
 * @param ctx  Packet context
 */
static
void free_pkt_ctx(pkt_ctx_t *ctx ODP_UNUSED)
{
}

#endif

/**
 * Check IPv4 address against a range/subnet
 *
 * @param addr  IPv4 address to check
 * @param range Pointer to address range to check against
 *
 * @return 1 if match else 0
 */
static
int match_ip_range(uint32_t addr, ip_addr_range_t *range)
{
	return (range->addr == (addr & range->mask));
}

/**
 * Query MAC address associated with an interface
 *
 * @param intf    String name of the interface
 * @param src_mac MAC address used by the interface
 *
 * @return 0 if successful else -1
 */
static
int query_mac_address(char *intf, uint8_t *src_mac)
{
	int sd;
	struct ifreq ifr;

	/* Get a socket descriptor */
	sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sd < 0) {
		ODP_ERR("Error: socket() failed for %s\n", intf);
		return -1;
	}

	/* Use ioctl() to look up interface name and get its MAC address */
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", intf);
	if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
		ODP_ERR("Error: ioctl() failed for %s\n", intf);
		return -1;
	}
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);

	/* Fini */
	close(sd);

	return 0;
}

/**
 * Parse text string representing a key into ODP key structure
 *
 * @param keystring  Pointer to key string to convert
 * @param key        Pointer to ODP key structure to populate
 * @param alg        Cipher/authentication algorithm associated with the key
 *
 * @return 0 if successful else -1
 */
static
int parse_key_string(char *keystring,
		     ipsec_key_t *key,
		     ipsec_alg_t *alg)
{
	int idx;
	char temp[3];

	if (alg->cipher && (alg->u.cipher == ODP_CIPHER_ALG_3DES_CBC))
		if (48 == strlen(keystring))
			key->length = 24;

	if (!alg->cipher && (alg->u.auth == ODP_AUTH_ALG_MD5_96))
		if (32 == strlen(keystring))
			key->length = 16;

	for (idx = 0; idx < key->length; idx++) {
		temp[0] = *keystring++;
		temp[1] = *keystring++;
		temp[2] = 0;
		key->data[idx] = strtol(temp, NULL, 16);
	}

	return key->length ? 0 : -1;
}

/**
 * Parse text string representing a MAC address into byte araray
 *
 * String is of the format "XX.XX.XX.XX.XX.XX" where XX is hexadecimal
 *
 * @param macaddress  Pointer to MAC address string to convert
 * @param mac         Pointer to MAC address byte array to populate
 *
 * @return 0 if successful else -1
 */
static
int parse_mac_string(char *macaddress, uint8_t *mac)
{
	int macwords[6];
	int converted;

	converted = sscanf(macaddress,
			   "%x.%x.%x.%x.%x.%x",
			   &macwords[0], &macwords[1], &macwords[2],
			   &macwords[3], &macwords[4], &macwords[5]);
	if (6 != converted)
		return -1;

	mac[0] = macwords[0];
	mac[1] = macwords[1];
	mac[2] = macwords[2];
	mac[3] = macwords[3];
	mac[4] = macwords[4];
	mac[5] = macwords[5];

	return 0;
}

/**
 * Parse text string representing an IPv4 address or subnet
 *
 * String is of the format "XXX.XXX.XXX.XXX(/W)" where
 * "XXX" is decimal value and "/W" is optional subnet length
 *
 * @param ipaddress  Pointer to IP address/subnet string to convert
 * @param addr       Pointer to return IPv4 address
 * @param mask       Pointer (optional) to return IPv4 mask
 *
 * @return 0 if successful else -1
 */
static
int parse_ipv4_string(char *ipaddress, uint32_t *addr, uint32_t *mask)
{
	int b[4];
	int qualifier = 32;
	int converted;

	if (strchr(ipaddress, '/')) {
		converted = sscanf(ipaddress, "%d.%d.%d.%d/%d",
				   &b[3], &b[2], &b[1], &b[0],
				   &qualifier);
		if (5 != converted)
			return -1;
	} else {
		converted = sscanf(ipaddress, "%d.%d.%d.%d",
				   &b[3], &b[2], &b[1], &b[0]);
		if (4 != converted)
			return -1;
	}

	if ((b[0] > 255) || (b[1] > 255) || (b[2] > 255) || (b[3] > 255))
		return -1;
	if (!qualifier || (qualifier > 32))
		return -1;

	*addr = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;
	if (mask)
		*mask = ~(0xFFFFFFFF & ((1ULL << (32 - qualifier)) - 1));

	return 0;
}

/**
 * Generate text string representing IPv4 address
 *
 * @param b    Pointer to buffer to store string
 * @param addr IPv4 address
 *
 * @return Pointer to supplied buffer
 */
static
char *ipv4_addr_str(char *b, uint32_t addr)
{
	sprintf(b, "%03d.%03d.%03d.%03d",
		0xFF & ((addr) >> 24),
		0xFF & ((addr) >> 16),
		0xFF & ((addr) >>  8),
		0xFF & ((addr) >>  0));
	return b;
}

/**
 * Generate text string representing IPv4 range/subnet, output
 * in "XXX.XXX.XXX.XXX/W" format
 *
 * @param b     Pointer to buffer to store string
 * @param range Pointer to IPv4 address range
 *
 * @return Pointer to supplied buffer
 */
static
char *ipv4_subnet_str(char *b, ip_addr_range_t *range)
{
	int idx;
	int len;

	for (idx = 0; idx < 32; idx++)
		if (range->mask & (1 << idx))
			break;
	len = 32 - idx;

	sprintf(b, "%03d.%03d.%03d.%03d/%d",
		0xFF & ((range->addr) >> 24),
		0xFF & ((range->addr) >> 16),
		0xFF & ((range->addr) >>  8),
		0xFF & ((range->addr) >>  0),
		len);
	return b;
}

/**
 * Generate text string representing MAC address
 *
 * @param b     Pointer to buffer to store string
 * @param mac   Pointer to MAC address
 *
 * @return Pointer to supplied buffer
 */
static
char *mac_addr_str(char *b, uint8_t *mac)
{
	sprintf(b, "%02X.%02X.%02X.%02X.%02X.%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return b;
}

/**
 * Parse loop interface index
 *
 * @param b     Pointer to buffer to parse
 *
 * @return interface index (0 to (MAX_LOOPBACK - 1)) else -1
 */
static
int loop_if_index(char *b)
{
	int ret;
	int idx;

	/* Derive loopback interface index */
	ret = sscanf(b, "loop%d", &idx);
	if ((1 != ret) || (idx >= MAX_LOOPBACK))
		return -1;
	return idx;
}

/**
 * Locate IPsec headers (AH and/or ESP) in packet
 *
 * @param ip     Pointer to packets IPv4 header
 * @param ah_p   Pointer to location to return AH header pointer
 * @param esp_p  Pointer to location to return ESP header pointer
 *
 * @return length of IPsec headers found
 */
static
int locate_ipsec_headers(odp_ipv4hdr_t *ip,
			 odp_ahhdr_t **ah_p,
			 odp_esphdr_t **esp_p)
{
	uint8_t *in = ipv4_data_p(ip);
	odp_ahhdr_t *ah = NULL;
	odp_esphdr_t *esp = NULL;

	if (ODP_IPPROTO_AH == ip->proto) {
		ah = (odp_ahhdr_t *)in;
		in += ((ah)->ah_len + 2) * 4;
		if (ODP_IPPROTO_ESP == ah->next_header) {
			esp = (odp_esphdr_t *)in;
			in += sizeof(odp_esphdr_t);
		}
	} else if (ODP_IPPROTO_ESP == ip->proto) {
		esp = (odp_esphdr_t *)in;
		in += sizeof(odp_esphdr_t);
	}

	*ah_p = ah;
	*esp_p = esp;
	return in - (ipv4_data_p(ip));
}

/**
 * Loopback database entry structure
 */
typedef struct loopback_db_entry_s {
	odp_queue_t   inq_def;
	odp_queue_t   outq_def;
	uint8_t       mac[6];
} loopback_db_entry_t;

typedef struct loopback_db_s {
	loopback_db_entry_t  intf[MAX_LOOPBACK];
} loopback_db_t;

static loopback_db_t *loopback_db;

/** Initialize loopback database global control structure */
static
void init_loopback_db(void)
{
	int idx;

	loopback_db = odp_shm_reserve("loopback_db",
				      sizeof(loopback_db_t),
				      ODP_CACHE_LINE_SIZE);
	if (loopback_db == NULL) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(loopback_db, 0, sizeof(*loopback_db));

	for (idx = 0; idx < MAX_LOOPBACK; idx++) {
		loopback_db->intf[idx].inq_def = ODP_QUEUE_INVALID;
		loopback_db->intf[idx].outq_def = ODP_QUEUE_INVALID;
	}
}
/**
 * Security Assocation (SA) data base entry
 */
typedef struct sa_db_entry_s {
	struct sa_db_entry_s *next;      /**< Next entry on list */
	uint32_t              src_ip;    /**< Source IPv4 address */
	uint32_t              dst_ip;    /**< Desitnation IPv4 address */
	uint32_t              spi;       /**< Security Parameter Index */
	ipsec_alg_t           alg;       /**< Cipher/auth algorithm */
	ipsec_key_t           key;       /**< Cipher/auth key */
	uint32_t              block_len; /**< Cipher block length */
	uint32_t              iv_len;    /**< Initialization Vector length */
	uint32_t              icv_len;   /**< Integrity Check Value length */
} sa_db_entry_t;

/**
 * Security Assocation (SA) data base global structure
 */
typedef struct sa_db_s {
	uint32_t         index;          /**< Index of next available entry */
	sa_db_entry_t   *list;           /**< List of active entries */
	sa_db_entry_t    array[MAX_DB];  /**< Entry storage */
} sa_db_t;

/** Global pointer to sa db */
static sa_db_t *sa_db;

/** Initialize SA database global control structure */
static
void init_sa_db(void)
{
	sa_db = odp_shm_reserve("shm_sa_db",
				sizeof(sa_db_t),
				ODP_CACHE_LINE_SIZE);
	if (sa_db == NULL) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(sa_db, 0, sizeof(*sa_db));
}

/**
 * Create an SA DB entry
 *
 * String is of the format "SrcIP:DstIP:Alg:SPI:Key"
 *
 * @param input  Pointer to string describing SA
 * @param cipher TRUE if cipher else FALSE for auth
 *
 * @return 0 if successful else -1
 */
static
int create_sa_db_entry(char *input, boolean cipher)
{
	int pos;
	char *local, *str, *save;
	sa_db_entry_t *entry = &sa_db->array[sa_db->index];

	/* Verify we have a good entry */
	if (MAX_DB <= sa_db->index)
		return -1;

	/* Make a local copy */
	local = malloc(strlen(input) + 1);
	if (local == NULL)
		return -1;
	strcpy(local, input);

	/* Set cipher versus auth */
	entry->alg.cipher = cipher;

	/* count the number of tokens separated by ',' */
	for (str = local, save = NULL, pos = 0;; str = NULL, pos++) {
		char *token = strtok_r(str, ":", &save);

		/* Check for no more tokens */
		if (token == NULL)
			break;

		/* Parse based on postion */
		switch (pos) {
		case 0:
			parse_ipv4_string(token, &entry->src_ip, NULL);
			break;
		case 1:
			parse_ipv4_string(token, &entry->dst_ip, NULL);
			break;
		case 2:
			if (cipher) {
				if (0 == strcmp(token, "3des")) {
					entry->alg.u.cipher =
						ODP_CIPHER_ALG_3DES_CBC;
					entry->block_len  = 8;
					entry->iv_len     = 8;
				} else {
					entry->alg.u.cipher =
						ODP_CIPHER_ALG_NULL;
				}
			} else {
				if (0 == strcmp(token, "md5")) {
					entry->alg.u.auth =
						ODP_AUTH_ALG_MD5_96;
					entry->icv_len    = 12;
				} else {
					entry->alg.u.auth = ODP_AUTH_ALG_NULL;
				}
			}
			break;
		case 3:
			entry->spi = strtol(token, NULL, 16);
			break;
		case 4:
			parse_key_string(token,
					 &entry->key,
					 &entry->alg);
			break;
		default:
			return -1;
		}
	}

	/* Verify all positions filled */
	if (5 != pos)
		return -1;

	/* Add route to the list */
	sa_db->index++;
	entry->next = sa_db->list;
	sa_db->list = entry;

	return 0;
}

/**
 * Display the SA DB
 */
static
void dump_sa_db(void)
{
	sa_db_entry_t *entry;

	printf("\n"
	       "Security association table\n"
	       "--------------------------\n");

	for (entry = sa_db->list; NULL != entry; entry = entry->next) {
		uint32_t idx;
		char src_ip_str[32];
		char dst_ip_str[32];
		uint8_t *p = entry->key.data;


		printf(" %s %s %s %X %d ",
		       entry->alg.cipher ? "esp" : "ah ",
		       ipv4_addr_str(src_ip_str, entry->src_ip),
		       ipv4_addr_str(dst_ip_str, entry->dst_ip),
		       entry->spi,
		       entry->alg.cipher ?
		       (int)entry->alg.u.cipher :
		       (int)entry->alg.u.auth);

		/* Brute force key display */
		for (idx = 0; idx < entry->key.length; idx++)
			printf("%02X", *p++);

		printf("\n");
	}
}

/**
 * Find a matching SA DB entry
 *
 * @param src    Pointer to source subnet/range
 * @param dst    Pointer to destination subnet/range
 * @param cipher TRUE if cipher else FALSE for auth
 *
 * @return pointer to SA DB entry else NULL
 */
static
sa_db_entry_t *find_sa_db_entry(ip_addr_range_t *src,
				ip_addr_range_t *dst,
				boolean cipher)
{
	sa_db_entry_t *entry = NULL;

	/* Scan all entries and return first match */
	for (entry = sa_db->list; NULL != entry; entry = entry->next) {
		if (cipher != entry->alg.cipher)
			continue;
		if (!match_ip_range(entry->src_ip, src))
			continue;
		if (!match_ip_range(entry->dst_ip, dst))
			continue;
		break;
	}
	return entry;
}

/**
 * Security Policy (SP) data base entry
 */
typedef struct sp_db_entry_s {
	struct sp_db_entry_s *next;        /**< Next entry on list */
	ip_addr_range_t       src_subnet;  /**< Source IPv4 subnet/range */
	ip_addr_range_t       dst_subnet;  /**< Destination IPv4 subnet/range */
	boolean               input;       /**< Direction when applied */
	boolean               esp;         /**< Enable cipher (ESP) */
	boolean               ah;          /**< Enable authentication (AH) */
} sp_db_entry_t;

/**
 * Security Policy (SP) data base global structure
 */
typedef struct sp_db_s {
	uint32_t         index;          /**< Index of next available entry */
	sp_db_entry_t   *list;		 /**< List of active entries */
	sp_db_entry_t    array[MAX_DB];	 /**< Entry storage */
} sp_db_t;

/** Global pointer to sp db */
static sp_db_t *sp_db;

/** Initialize SP database global control structure */
static
void init_sp_db(void)
{
	sp_db = odp_shm_reserve("shm_sp_db",
				sizeof(sp_db_t),
				ODP_CACHE_LINE_SIZE);
	if (sp_db == NULL) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(sp_db, 0, sizeof(*sp_db));
}

/**
 * Create an SP DB entry
 *
 * String is of the format "SrcSubNet:DstSubNet:(in|out):(ah|esp|both)"
 *
 * @param input  Pointer to string describing SP
 *
 * @return 0 if successful else -1
 */
static
int create_sp_db_entry(char *input)
{
	int pos;
	char *local, *str, *save;
	sp_db_entry_t *entry = &sp_db->array[sp_db->index];

	/* Verify we have a good entry */
	if (MAX_DB <= sp_db->index)
		return -1;

	/* Make a local copy */
	local = malloc(strlen(input) + 1);
	if (local == NULL)
		return -1;
	strcpy(local, input);

	/* count the number of tokens separated by ',' */
	for (str = local, save = NULL, pos = 0;; str = NULL, pos++) {
		char *token = strtok_r(str, ":", &save);

		/* Check for no more tokens */
		if (token == NULL)
			break;

		/* Parse based on postion */
		switch (pos) {
		case 0:
			parse_ipv4_string(token,
					  &entry->src_subnet.addr,
					  &entry->src_subnet.mask);
			break;
		case 1:
			parse_ipv4_string(token,
					  &entry->dst_subnet.addr,
					  &entry->dst_subnet.mask);
			break;
		case 2:
			if (0 == strcmp(token, "in"))
				entry->input = TRUE;
			else
				entry->input = FALSE;
			break;
		case 3:
			if (0 == strcmp(token, "esp")) {
				entry->esp = TRUE;
			} else if (0 == strcmp(token, "ah")) {
				entry->ah = TRUE;
			} else if (0 == strcmp(token, "both")) {
				entry->esp = TRUE;
				entry->ah = TRUE;
			}
			break;
		default:
			return -1;
		}
	}

	/* Verify all positions filled */
	if (4 != pos)
		return -1;

	/* Add route to the list */
	sp_db->index++;
	entry->next = sp_db->list;
	sp_db->list = entry;

	return 0;
}

/**
 * Display one SP DB entry
 *
 * @param entry  Pointer to entry to display
 */
static
void dump_sp_db_entry(sp_db_entry_t *entry)
{
	char src_subnet_str[32];
	char dst_subnet_str[32];

	printf(" %s %s %s %s:%s\n",
	       ipv4_subnet_str(src_subnet_str, &entry->src_subnet),
	       ipv4_subnet_str(dst_subnet_str, &entry->dst_subnet),
	       entry->input ? "in" : "out",
	       entry->esp ? "esp" : "none",
	       entry->ah ? "ah" : "none");
}

/**
 * Display the SP DB
 */
static
void dump_sp_db(void)
{
	sp_db_entry_t *entry;

	printf("\n"
	       "Security policy table\n"
	       "---------------------\n");

	for (entry = sp_db->list; NULL != entry; entry = entry->next)
		dump_sp_db_entry(entry);
}

/**
 * IPsec cache data base entry
 */
typedef struct ipsec_cache_entry_s {
	struct ipsec_cache_entry_s  *next;        /**< Next entry on list */
	boolean                      in_place;    /**< Crypto API mode */
	uint32_t                     src_ip;      /**< Source v4 address */
	uint32_t                     dst_ip;      /**< Destination v4 address */
	struct {
		enum  odp_cipher_alg alg;         /**< Cipher algorithm */
		uint32_t             spi;         /**< Cipher SPI */
		uint32_t             block_len;   /**< Cipher block length */
		uint32_t             iv_len;      /**< Cipher IV length */
		ipsec_key_t          key;         /**< Cipher key */
	} esp;
	struct {
		enum  odp_auth_alg   alg;         /**< Auth algorithm */
		uint32_t             spi;         /**< Auth SPI */
		uint32_t             icv_len;     /**< Auth ICV length */
		ipsec_key_t          key;         /**< Auth key */
	} ah;

	/* Per SA state */
	struct {
		odp_crypto_session_t session;     /**< Crypto session handle */
		uint32_t             esp_seq;     /**< ESP TX sequence number */
		uint32_t             ah_seq;      /**< AH TX sequence number */
		uint8_t              iv[32];      /**< ESP IV storage */
	} state;
} ipsec_cache_entry_t;

/**
 * IPsec cache data base global structure
 */
typedef struct ipsec_cache_s {
	uint32_t             index;       /**< Index of next available entry */
	ipsec_cache_entry_t *in_list;     /**< List of active input entries*/
	ipsec_cache_entry_t *out_list;    /**< List of active output entries*/
	ipsec_cache_entry_t  array[MAX_DB]; /**< Entry storage */
} ipsec_cache_t;

/** Global pointer to ipsec_cache db */
static ipsec_cache_t *ipsec_cache;

/** Initialize IPsec cache */
static
void init_ipsec_cache(void)
{
	ipsec_cache = odp_shm_reserve("shm_ipsec_cache",
				      sizeof(ipsec_cache_t),
				      ODP_CACHE_LINE_SIZE);
	if (ipsec_cache == NULL) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(ipsec_cache, 0, sizeof(*ipsec_cache));
}

/**
 * Create an entry in the IPsec cache
 *
 * @param cipher_sa   Cipher SA DB entry pointer
 * @param auth_sa     Auth SA DB entry pointer
 * @param api_mode    Crypto API mode for testing
 * @param in          Direction (input versus output)
 *
 * @return 0 if successful else -1
 */
static
int create_ipsec_cache_entry(sa_db_entry_t *cipher_sa,
			     sa_db_entry_t *auth_sa,
			     crypto_api_mode_e api_mode,
			     boolean in)
{
	odp_crypto_session_params_t params;
	ipsec_cache_entry_t *entry;
	enum odp_crypto_ses_create_err ses_create_rc;
	odp_crypto_session_t session;

	/* Verify we have a good entry */
	entry = &ipsec_cache->array[ipsec_cache->index];
	if (MAX_DB <= ipsec_cache->index)
		return -1;

	/* Setup parameters and call crypto library to create session */
	params.op = (in) ? ODP_CRYPTO_OP_DECODE : ODP_CRYPTO_OP_ENCODE;
	params.auth_cipher_text = TRUE;
	if (CRYPTO_API_SYNC == api_mode) {
		params.pref_mode   = ODP_CRYPTO_SYNC;
		params.compl_queue = ODP_QUEUE_INVALID;
		params.output_pool = ODP_BUFFER_POOL_INVALID;
	} else {
		params.pref_mode   = ODP_CRYPTO_ASYNC;
		params.compl_queue = completionq;
		params.output_pool = out_pool;
	}

	if (CRYPTO_API_ASYNC_NEW_BUFFER == api_mode)
		entry->in_place = FALSE;
	else
		entry->in_place = TRUE;


	/* Cipher */
	if (cipher_sa) {
		params.cipher_alg  = cipher_sa->alg.u.cipher;
		params.cipher_key.data  = cipher_sa->key.data;
		params.cipher_key.length  = cipher_sa->key.length;
		params.iv.data = entry->state.iv;
		params.iv.length = cipher_sa->iv_len;
	} else {
		params.cipher_alg = ODP_CIPHER_ALG_NULL;
		params.iv.data = NULL;
		params.iv.length = 0;
	}

	/* Auth */
	if (auth_sa) {
		params.auth_alg = auth_sa->alg.u.auth;
		params.auth_key.data = auth_sa->key.data;
		params.auth_key.length = auth_sa->key.length;
	} else {
		params.auth_alg = ODP_AUTH_ALG_NULL;
	}

	/* Generate an IV */
	if (params.iv.length) {
		size_t size = params.iv.length;

		odp_hw_random_get(params.iv.data, &size, 1);
	}

	/* Synchronous session create for now */
	if (odp_crypto_session_create(&params, &session, &ses_create_rc))
		return -1;
	if (ODP_CRYPTO_SES_CREATE_ERR_NONE != ses_create_rc)
		return -1;

	/* Copy remainder */
	if (cipher_sa) {
		entry->src_ip = cipher_sa->src_ip;
		entry->dst_ip = cipher_sa->dst_ip;
		entry->esp.alg = cipher_sa->alg.u.cipher;
		entry->esp.spi = cipher_sa->spi;
		entry->esp.block_len = cipher_sa->block_len;
		entry->esp.iv_len = cipher_sa->iv_len;
		memcpy(&entry->esp.key, &cipher_sa->key, sizeof(ipsec_key_t));
	}
	if (auth_sa) {
		entry->src_ip = auth_sa->src_ip;
		entry->dst_ip = auth_sa->dst_ip;
		entry->ah.alg = auth_sa->alg.u.auth;
		entry->ah.spi = auth_sa->spi;
		entry->ah.icv_len = auth_sa->icv_len;
		memcpy(&entry->ah.key, &auth_sa->key, sizeof(ipsec_key_t));
	}

	/* Initialize state */
	entry->state.esp_seq = 0;
	entry->state.ah_seq = 0;
	entry->state.session = session;

	/* Add entry to the appropriate list */
	ipsec_cache->index++;
	if (in) {
		entry->next = ipsec_cache->in_list;
		ipsec_cache->in_list = entry;
	} else {
		entry->next = ipsec_cache->out_list;
		ipsec_cache->out_list = entry;
	}

	return 0;
}

/**
 * Find a matching IPsec cache entry for input packet
 *
 * @param src_ip    Source IPv4 address
 * @param dst_ip    Destination IPv4 address
 * @param ah        Pointer to AH header in packet else NULL
 * @param esp       Pointer to ESP header in packet else NULL
 *
 * @return pointer to IPsec cache entry else NULL
 */
static
ipsec_cache_entry_t *find_ipsec_cache_entry_in(uint32_t src_ip,
					       uint32_t dst_ip,
					       odp_ahhdr_t *ah,
					       odp_esphdr_t *esp)
{
	ipsec_cache_entry_t *entry = ipsec_cache->in_list;

	/* Look for a hit */
	for (; NULL != entry; entry = entry->next) {
		if ((entry->src_ip != src_ip) || (entry->dst_ip != dst_ip))
			continue;
		if (ah &&
		    ((!entry->ah.alg) ||
		     (entry->ah.spi != odp_be_to_cpu_32(ah->spi))))
			continue;
		if (esp &&
		    ((!entry->esp.alg) ||
		     (entry->esp.spi != odp_be_to_cpu_32(esp->spi))))
			continue;
		break;
	}

	return entry;
}

/**
 * Find a matching IPsec cache entry for output packet
 *
 * @param src_ip    Source IPv4 address
 * @param dst_ip    Destination IPv4 address
 * @param proto     IPv4 protocol (currently all protocols match)
 *
 * @return pointer to IPsec cache entry else NULL
 */
static
ipsec_cache_entry_t *find_ipsec_cache_entry_out(uint32_t src_ip,
						uint32_t dst_ip,
						uint8_t proto ODP_UNUSED)
{
	ipsec_cache_entry_t *entry = ipsec_cache->out_list;

	/* Look for a hit */
	for (; NULL != entry; entry = entry->next) {
		if ((entry->src_ip == src_ip) && (entry->dst_ip == dst_ip))
			break;
	}
	return entry;
}

/**
 * Forwarding data base entry
 */
typedef struct fwd_db_entry_s {
	struct fwd_db_entry_s *next;          /**< Next entry on list */
	char                  *oif;           /**< Output interface name */
	odp_queue_t            queue;         /**< Output transmit queue */
	uint8_t                src_mac[6];    /**< Output source MAC */
	uint8_t                dst_mac[6];    /**< Output destination MAC */
	ip_addr_range_t        subnet;        /**< Subnet for this router */
} fwd_db_entry_t;

/**
 * Forwarding data base global structure
 */
typedef struct fwd_db_s {
	uint32_t          index;          /**< Next available entry */
	fwd_db_entry_t   *list;           /**< List of active routes */
	fwd_db_entry_t    array[MAX_DB];  /**< Entry storage */
} fwd_db_t;

/** Global pointer to fwd db */
static fwd_db_t *fwd_db;

/** Initialize FWD DB */
static
void init_fwd_db(void)
{
	fwd_db = odp_shm_reserve("shm_fwd_db",
				 sizeof(fwd_db_t),
				 ODP_CACHE_LINE_SIZE);
	if (fwd_db == NULL) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(fwd_db, 0, sizeof(*fwd_db));
}

/**
 * Create a forwarding database entry
 *
 * String is of the format "SubNet:Intf:NextHopMAC"
 *
 * @param input  Pointer to string describing route
 *
 * @return 0 if successful else -1
 */
static
int create_fwd_db_entry(char *input)
{
	int pos;
	char *local, *str, *save;
	fwd_db_entry_t *entry = &fwd_db->array[fwd_db->index];

	/* Verify we haven't run out of space */
	if (MAX_DB <= fwd_db->index)
		return -1;

	/* Make a local copy */
	local = malloc(strlen(input) + 1);
	if (local == NULL)
		return -1;
	strcpy(local, input);

	/* count the number of tokens separated by ',' */
	for (str = local, save = NULL, pos = 0;; str = NULL, pos++) {
		char *token = strtok_r(str, ":", &save);

		/* Check for no more tokens */
		if (token == NULL)
			break;

		/* Parse based on postion */
		switch (pos) {
		case 0:
			parse_ipv4_string(token,
					  &entry->subnet.addr,
					  &entry->subnet.mask);
			break;
		case 1:
			entry->oif = token;
			break;
		case 2:
			parse_mac_string(token, entry->dst_mac);
			break;
		default:
			return -1;
		}
	}

	/* Verify all positions filled */
	if (3 != pos)
		return -1;

	/* Reset queue to invalid */
	entry->queue = ODP_QUEUE_INVALID;

	/* Add route to the list */
	fwd_db->index++;
	entry->next = fwd_db->list;
	fwd_db->list = entry;

	return 0;
}

/**
 * Scan FWD DB entries and resolve output queue and source MAC address
 *
 * @param intf   Interface name string
 * @param outq   Output queue for packet transmit
 * @param mac    MAC address of this interface
 */
static
void resolve_fwd_db(char *intf, odp_queue_t outq, uint8_t *mac)
{
	fwd_db_entry_t *entry;

	/* Walk the list and attempt to set output queue and MAC */
	for (entry = fwd_db->list; NULL != entry; entry = entry->next) {
		if (strcmp(intf, entry->oif))
			continue;

		entry->queue = outq;
		memcpy(entry->src_mac, mac, 6);
	}
}

/**
 * Display one fowarding database entry
 *
 * @param entry  Pointer to entry to display
 */
static
void dump_fwd_db_entry(fwd_db_entry_t *entry)
{
	char subnet_str[32];
	char mac_str[32];

	printf(" %s %s %s\n",
	       ipv4_subnet_str(subnet_str, &entry->subnet),
	       entry->oif,
	       mac_addr_str(mac_str, entry->dst_mac));
}

/**
 * Display the forwarding database
 */
static
void dump_fwd_db(void)
{
	fwd_db_entry_t *entry;

	printf("\n"
	       "Routing table\n"
	       "-------------\n");

	for (entry = fwd_db->list; NULL != entry; entry = entry->next)
		dump_fwd_db_entry(entry);
}

/**
 * Find a matching forwarding database entry
 *
 * @param dst_ip  Destination IPv4 address
 *
 * @return pointer to forwarding DB entry else NULL
 */
static
fwd_db_entry_t *find_fwd_db_entry(uint32_t dst_ip)
{
	fwd_db_entry_t *entry;

	for (entry = fwd_db->list; NULL != entry; entry = entry->next)
		if (entry->subnet.addr == (dst_ip & entry->subnet.mask))
			break;
	return entry;
}

/**
 * Stream database entry structure
 */
typedef struct stream_db_entry_s {
	struct stream_db_entry_s *next; /**< Next entry on list */
	int              id;            /**< Stream ID */
	uint32_t         src_ip;        /**< Source IPv4 address */
	uint32_t         dst_ip;        /**< Destination IPv4 address */
	int              count;         /**< Packet count */
	uint             length;        /**< Packet payload length */
	uint32_t         created;       /**< Number successfully created */
	uint32_t         verified;      /**< Number successfully verified */
	struct {
		int      loop;          /**< Input loop interface index */
		uint32_t ah_seq;        /**< AH sequence number if present */
		uint32_t esp_seq;       /**< ESP sequence number if present */
		ipsec_cache_entry_t *entry;  /**< IPsec to apply on input */
	} input;
	struct {
		int      loop;          /**< Output loop interface index */
		ipsec_cache_entry_t *entry;  /**t IPsec to verify on output */
	} output;
} stream_db_entry_t;

/**
 * Stream database
 */
typedef struct stream_db_s {
	uint32_t           index;          /**< Index of next available entry */
	stream_db_entry_t *list;           /**< List of active entries */
	stream_db_entry_t  array[MAX_DB];  /**< Entry storage */
} stream_db_t;

static stream_db_t *stream_db;

/** Initialize stream database global control structure */
static
void init_stream_db(void)
{
	stream_db = odp_shm_reserve("stream_db",
				    sizeof(stream_db_t),
				    ODP_CACHE_LINE_SIZE);
	if (stream_db == NULL) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(stream_db, 0, sizeof(*stream_db));
}

/**
 * Create an stream DB entry
 *
 * String is of the format "SrcIP:DstIP:InInt:OutIntf:Count:Length"
 *
 * @param input  Pointer to string describing stream
 *
 * @return 0 if successful else -1
 */
static
int create_stream_db_entry(char *input)
{
	int pos;
	char *local, *str, *save;
	stream_db_entry_t *entry = &stream_db->array[stream_db->index];

	/* Verify we have a good entry */
	if (MAX_DB <= stream_db->index)
		return -1;

	/* Make a local copy */
	local = malloc(strlen(input) + 1);
	if (local == NULL)
		return -1;
	strcpy(local, input);

	/* count the number of tokens separated by ',' */
	for (str = local, save = NULL, pos = 0;; str = NULL, pos++) {
		char *token = strtok_r(str, ":", &save);

		/* Check for no more tokens */
		if (token == NULL)
			break;

		/* Parse based on postion */
		switch (pos) {
		case 0:
			parse_ipv4_string(token, &entry->src_ip, NULL);
			break;
		case 1:
			parse_ipv4_string(token, &entry->dst_ip, NULL);
			break;
		case 2:
			entry->input.loop = loop_if_index(token);
			if (entry->input.loop < 0) {
				ODP_ERR("Error: stream must have input loop\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 3:
			entry->output.loop = loop_if_index(token);
			break;
		case 4:
			entry->count = atoi(token);
			break;
		case 5:
			entry->length = atoi(token);
			if (entry->length < sizeof(stream_pkt_hdr_t))
				entry->length = 0;
			else
				entry->length -= sizeof(stream_pkt_hdr_t);
			break;
		default:
			return -1;
		}
	}

	/* Verify all positions filled */
	if (6 != pos)
		return -1;

	/* Add stream to the list */
	entry->id = stream_db->index++;
	entry->next = stream_db->list;
	stream_db->list = entry;

	return 0;
}

/**
 * Create IPv4 packet for stream
 *
 * Create one ICMP test packet based on the stream structure.  If an input
 * IPsec cache entry is associated with the stream, build a packet that should
 * successfully match that entry and be correctly decoded by it.
 *
 * @param stream    Stream DB entry
 * @param pkt_pool  Packet buffer pool to allocate from
 *
 * @return packet else ODP_PACKET_INVALID
 */
static
odp_packet_t create_ipv4_packet(stream_db_entry_t *stream,
				odp_buffer_pool_t pkt_pool)
{
	ipsec_cache_entry_t *entry = stream->input.entry;
	odp_buffer_t         bfr;
	odp_packet_t         pkt;
	uint8_t             *base;
	uint8_t             *data;
	uint8_t             *dmac;
	odp_ethhdr_t        *eth;
	odp_ipv4hdr_t       *ip;
	odp_ahhdr_t         *ah = NULL;
	odp_esphdr_t        *esp = NULL;
	odp_icmphdr_t       *icmp;
	stream_pkt_hdr_t    *test;
	uint                 i;

	/* Get destination MAC address to use */
	dmac = loopback_db->intf[stream->input.loop].mac;

	/* Get buffer */
	bfr = odp_buffer_alloc(pkt_pool);
	if (ODP_BUFFER_INVALID == bfr)
		return ODP_PACKET_INVALID;
	pkt = odp_packet_from_buffer(bfr);
	odp_packet_init(pkt);
	base = odp_packet_start(pkt);
	data = odp_packet_start(pkt);

	/* Ethernet */
	odp_packet_set_l2_offset(pkt, data - base);
	eth = (odp_ethhdr_t *)data;
	data += sizeof(*eth);

	memset((char *)eth->src.addr, (0x80 | stream->id), ODP_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, dmac, ODP_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODP_ETHTYPE_IPV4);

	/* IPv4 */
	odp_packet_set_l3_offset(pkt, data - base);
	ip = (odp_ipv4hdr_t *)data;
	data += sizeof(*ip);
	odp_packet_set_l4_offset(pkt, data - base);

	/* Wait until almost finished to fill in mutable fields */
	memset((char *)ip, 0, sizeof(*ip));
	ip->ver_ihl = 0x45;
	ip->proto = ODP_IPPROTO_ICMP;
	ip->id = odp_cpu_to_be_16(stream->id);
	ip->src_addr = odp_cpu_to_be_32(stream->src_ip);
	ip->dst_addr = odp_cpu_to_be_32(stream->dst_ip);

	/* AH (if specified) */
	if (entry && (ODP_AUTH_ALG_NULL != entry->ah.alg)) {
		if (ODP_AUTH_ALG_MD5_96 != entry->ah.alg)
			abort();

		ah = (odp_ahhdr_t *)data;
		data += sizeof(*ah);
		data += entry->ah.icv_len;

		memset((char *)ah, 0, sizeof(*ah) + entry->ah.icv_len);
		ah->ah_len = 1 + (entry->ah.icv_len / 4);
		ah->spi = odp_cpu_to_be_32(entry->ah.spi);
		ah->seq_no = odp_cpu_to_be_32(stream->input.ah_seq++);
	}

	/* ESP (if specified) */
	if (entry && (ODP_CIPHER_ALG_NULL != entry->esp.alg)) {
		if (ODP_CIPHER_ALG_3DES_CBC != entry->esp.alg)
			abort();

		esp = (odp_esphdr_t *)data;
		data += sizeof(*esp);
		data += entry->esp.iv_len;

		esp->spi = odp_cpu_to_be_32(entry->esp.spi);
		esp->seq_no = odp_cpu_to_be_32(stream->input.esp_seq++);
		RAND_bytes(esp->iv, 8);
	}

	/* ICMP header so we can see it on wireshark */
	icmp = (odp_icmphdr_t *)data;
	data += sizeof(*icmp);
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = odp_cpu_to_be_16(0x1234);
	icmp->un.echo.sequence = odp_cpu_to_be_16(stream->created);

	/* Packet payload of incrementing bytes */
	test = (stream_pkt_hdr_t *)data;
	data += sizeof(*test);
	test->magic = odp_cpu_to_be_64(STREAM_MAGIC);
	for (i = 0; i < stream->length; i++)
		*data++ = (uint8_t)i;

	/* Close ICMP */
	icmp->chksum = 0;
	icmp->chksum = odp_chksum(icmp, data - (uint8_t *)icmp);

	/* Close ESP if specified */
	if (esp) {
		int payload_len = data - (uint8_t *)icmp;
		int encrypt_len;
		odp_esptrl_t *esp_t;
		DES_key_schedule ks1, ks2, ks3;
		uint8_t iv[8];

		memcpy(iv, esp->iv, sizeof(iv));

		encrypt_len = ESP_ENCODE_LEN(payload_len + sizeof(*esp_t),
					     entry->esp.block_len);
		memset(data, 0, encrypt_len - payload_len);
		data += encrypt_len - payload_len;

		esp_t = (odp_esptrl_t *)(data) - 1;
		esp_t->pad_len = encrypt_len - payload_len - sizeof(*esp_t);
		esp_t->next_header = ip->proto;
		ip->proto = ODP_IPPROTO_ESP;

		DES_set_key((DES_cblock *)&entry->esp.key.data[0], &ks1);
		DES_set_key((DES_cblock *)&entry->esp.key.data[8], &ks2);
		DES_set_key((DES_cblock *)&entry->esp.key.data[16], &ks3);

		DES_ede3_cbc_encrypt((uint8_t *)icmp,
				     (uint8_t *)icmp,
				     encrypt_len,
				     &ks1,
				     &ks2,
				     &ks3,
				     (DES_cblock *)iv,
				     1);
	}

	/* Since ESP can pad we can now fix IP length */
	ip->tot_len = odp_cpu_to_be_16(data - (uint8_t *)ip);
	odp_packet_set_len(pkt, data - base);

	/* Close AH if specified */
	if (ah) {
		uint8_t hash[EVP_MAX_MD_SIZE];
		uint32_t hash_len = 12;
		int auth_len = data - (uint8_t *)ip;

		ah->next_header = ip->proto;
		ip->proto = ODP_IPPROTO_AH;

		HMAC(EVP_md5(),
		     entry->ah.key.data,
		     16,
		     (uint8_t *)ip,
		     auth_len,
		     hash,
		     &hash_len);

		memcpy(ah->icv, hash, 12);
	}

	/* Now fill in final IP header fields */
	ip->ttl = 64;
	ip->tos = 0;
	ip->frag_offset = 0;
	ip->chksum = 0;
	odp_ipv4_csum_update(pkt);
	return pkt;
}

/**
 * Resolve the stream DB against the IPsec input and output caches
 *
 * For each stream, look the source and destination IP address up in the
 * input and output IPsec caches.  If a hit is found, store the hit in
 * the stream DB to be used when creating packets.
 */
static
void resolve_stream_db(void)
{
	stream_db_entry_t *stream = NULL;

	/* For each stream look for input and output IPsec entries */
	for (stream = stream_db->list; NULL != stream; stream = stream->next) {
		ipsec_cache_entry_t *entry;

		/* Lookup input entry */
		entry = find_ipsec_cache_entry_in(stream->src_ip,
						  stream->dst_ip,
						  NULL,
						  NULL);
		stream->input.entry = entry;

		/* Lookup output entry */
		entry = find_ipsec_cache_entry_out(stream->src_ip,
						   stream->dst_ip,
						   0);
		stream->output.entry = entry;
	}
}

/**
 * Create input packets based on the stream DB
 *
 * Create input packets based on the configured streams and enqueue them
 * into loop interface input queues.  Once packet processing starts these
 * packets will be remomved and processed as if they had come from a normal
 * packet interface.
 *
 * @return number of streams successfully processed
 */
static
int create_stream_db_inputs(void)
{
	int created = 0;
	odp_buffer_pool_t pkt_pool;
	stream_db_entry_t *stream = NULL;

	/* Lookup the packet pool */
	pkt_pool = odp_buffer_pool_lookup("packet_pool");
	if (pkt_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Error: pkt_pool not found\n");
		exit(EXIT_FAILURE);
	}

	/* For each stream create corresponding input packets */
	for (stream = stream_db->list; NULL != stream; stream = stream->next) {
		int count;
		odp_queue_t queue;

		queue = loopback_db->intf[stream->input.loop].inq_def;

		for (count = stream->count; count > 0; count--) {
			odp_packet_t pkt;

			pkt = create_ipv4_packet(stream, pkt_pool);
			if (ODP_PACKET_INVALID == pkt) {
				printf("Packet buffers exhausted\n");
				break;
			}
			stream->created++;
			odp_queue_enq(queue, pkt);

			/* Count this stream when we create first packet */
			if (1 == stream->created)
				created++;
		}
	}

	return created;
}

/**
 * Verify an IPv4 packet received on a loop output queue
 *
 * TODO: Better error checking, add counters, add tracing,
 *       add order verification
 *
 * @param stream  Stream to verify the packet against
 * @param pkt     Packet to verify
 *
 * @return TRUE if packet verifies else FALSE
 */
static
boolean verify_ipv4_packet(stream_db_entry_t *stream,
			   odp_packet_t pkt)
{
	ipsec_cache_entry_t *entry = stream->output.entry;
	uint8_t             *data;
	odp_ipv4hdr_t       *ip;
	odp_ahhdr_t         *ah = NULL;
	odp_esphdr_t        *esp = NULL;
	int                  hdr_len;
	odp_icmphdr_t       *icmp;
	stream_pkt_hdr_t    *test;

	/* Basic IPv4 verify (add checksum verification) */
	data = odp_packet_l3(pkt);
	ip = (odp_ipv4hdr_t *)data;
	data += sizeof(*ip);
	if (0x45 != ip->ver_ihl)
		return FALSE;
	if (stream->src_ip != odp_be_to_cpu_32(ip->src_addr))
		return FALSE;
	if (stream->dst_ip != odp_be_to_cpu_32(ip->dst_addr))
		return FALSE;

	/* Find IPsec headers if any and compare against entry */
	hdr_len = locate_ipsec_headers(ip, &ah, &esp);
	if (ah) {
		if (!entry)
			return FALSE;
		if (ODP_AUTH_ALG_NULL == entry->ah.alg)
			return FALSE;
		if (odp_be_to_cpu_32(ah->spi) != entry->ah.spi)
			return FALSE;
		if (ODP_AUTH_ALG_MD5_96 != entry->ah.alg)
			abort();
	} else {
		if (entry && (ODP_AUTH_ALG_NULL != entry->ah.alg))
			return FALSE;
	}
	if (esp) {
		if (!entry)
			return FALSE;
		if (ODP_CIPHER_ALG_NULL == entry->esp.alg)
			return FALSE;
		if (odp_be_to_cpu_32(esp->spi) != entry->esp.spi)
			return FALSE;
		if (ODP_CIPHER_ALG_3DES_CBC != entry->esp.alg)
			abort();
		hdr_len += entry->esp.iv_len;
	} else {
		if (entry && (ODP_CIPHER_ALG_NULL != entry->esp.alg))
			return FALSE;
	}
	data += hdr_len;

	/* Verify authentication (if present) */
	if (ah) {
		uint8_t  ip_tos;
		uint8_t  ip_ttl;
		uint16_t ip_frag_offset;
		uint8_t  icv[12];
		uint8_t  hash[EVP_MAX_MD_SIZE];
		uint32_t hash_len = 12;

		/* Save/clear mutable fields */
		ip_tos = ip->tos;
		ip_ttl = ip->ttl;
		ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
		ip->tos = 0;
		ip->ttl = 0;
		ip->frag_offset = 0;
		ip->chksum = 0;
		memcpy(icv, ah->icv, 12);
		memset(ah->icv, 0, 12);

		/* Calculate HMAC and compare */
		HMAC(EVP_md5(),
		     entry->ah.key.data,
		     entry->ah.key.length,
		     (uint8_t *)ip,
		     odp_be_to_cpu_16(ip->tot_len),
		     hash,
		     &hash_len);

		if (0 != memcmp(icv, hash, sizeof(icv)))
			return FALSE;

		ip->proto = ah->next_header;
		ip->tos = ip_tos;
		ip->ttl = ip_ttl;
		ip->frag_offset = odp_cpu_to_be_16(ip_frag_offset);
	}

	/* Decipher if present */
	if (esp) {
		odp_esptrl_t *esp_t;
		DES_key_schedule ks1, ks2, ks3;
		uint8_t iv[8];
		int encrypt_len = ipv4_data_len(ip) - hdr_len;

		memcpy(iv, esp->iv, sizeof(iv));

		DES_set_key((DES_cblock *)&entry->esp.key.data[0], &ks1);
		DES_set_key((DES_cblock *)&entry->esp.key.data[8], &ks2);
		DES_set_key((DES_cblock *)&entry->esp.key.data[16], &ks3);

		DES_ede3_cbc_encrypt((uint8_t *)data,
				     (uint8_t *)data,
				     encrypt_len,
				     &ks1,
				     &ks2,
				     &ks3,
				     (DES_cblock *)iv,
				     0);

		esp_t = (odp_esptrl_t *)(data + encrypt_len) - 1;
		ip->proto = esp_t->next_header;
	}

	/* Verify ICMP packet */
	if (ODP_IPPROTO_ICMP != ip->proto)
		return FALSE;

	/* Verify ICMP header */
	icmp = (odp_icmphdr_t *)data;
	data += sizeof(*icmp);
	if (ICMP_ECHO != icmp->type)
		return FALSE;
	if (0x1234 != odp_be_to_cpu_16(icmp->un.echo.id))
		return FALSE;

	/* Now check our packet */
	test = (stream_pkt_hdr_t *)data;
	if (STREAM_MAGIC != odp_be_to_cpu_64(test->magic))
		return FALSE;

	return TRUE;
}

/**
 * Verify stream DB outputs
 *
 * For each stream, poll the output loop interface queue and verify
 * any packets found on it
 *
 * @return TRUE if all packets on all streams verified else FALSE
 */
static
boolean verify_stream_db_outputs(void)
{
	boolean done = TRUE;
	stream_db_entry_t *stream = NULL;

	/* For each stream look for output packets */
	for (stream = stream_db->list; NULL != stream; stream = stream->next) {
		int idx;
		int count;
		odp_queue_t queue;
		odp_buffer_t buf_tbl[32];

		queue = loopback_db->intf[stream->output.loop].outq_def;

		if (ODP_QUEUE_INVALID == queue)
			continue;

		for (;;) {
#if LOOP_DEQ_MULTIPLE
			count = odp_queue_deq_multi(queue, buf_tbl, 32);
#else
			buf_tbl[0] = odp_queue_deq(queue);
			count = (buf_tbl[0] != ODP_BUFFER_INVALID) ? 1 : 0;
#endif
			if (!count)
				break;
			for (idx = 0; idx < count; idx++) {
				boolean good;
				odp_packet_t pkt;

				pkt = odp_packet_from_buffer(buf_tbl[idx]);

				good = verify_ipv4_packet(stream, pkt);
				if (good)
					stream->verified++;
				odp_packet_free(pkt);
			}
		}

		printf("Stream %d %d\n", stream->created, stream->verified);

		if (stream->created != stream->verified)
			done = FALSE;
	}
	return done;
}

/**
 * IPsec pre argument processing intialization
 */
static
void ipsec_init_pre(void)
{
	odp_queue_param_t qparam;
	void *pool_base;

	/*
	 * Create queues
	 *
	 *  - completion queue (should eventually be ORDERED)
	 *  - sequence number queue (must be ATOMIC)
	 */
	qparam.sched.prio  = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;

	completionq = QUEUE_CREATE("completion",
				   ODP_QUEUE_TYPE_SCHED,
				   &qparam);
	if (completionq == ODP_QUEUE_INVALID) {
		ODP_ERR("Error: completion queue creation failed\n");
		exit(EXIT_FAILURE);
	}

	qparam.sched.prio  = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;

	seqnumq = QUEUE_CREATE("seqnum",
			       ODP_QUEUE_TYPE_SCHED,
			       &qparam);
	if (seqnumq == ODP_QUEUE_INVALID) {
		ODP_ERR("Error: sequence number queue creation failed\n");
		exit(EXIT_FAILURE);
	}

	/* Create output buffer pool */
	pool_base = odp_shm_reserve("shm_out_pool",
				    SHM_OUT_POOL_SIZE, ODP_CACHE_LINE_SIZE);

	out_pool = odp_buffer_pool_create("out_pool", pool_base,
					  SHM_OUT_POOL_SIZE,
					  SHM_OUT_POOL_BUF_SIZE,
					  ODP_CACHE_LINE_SIZE,
					  ODP_BUFFER_TYPE_PACKET);

	if (out_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Error: message pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Initialize our data bases */
	init_sp_db();
	init_sa_db();
	init_ipsec_cache();
}

/**
 * IPsec post argument processing intialization
 *
 * Resolve SP DB with SA DB and create corresponding IPsec cache entries
 *
 * @param api_mode  Mode to use when invoking per packet crypto API
 */
static
void ipsec_init_post(crypto_api_mode_e api_mode)
{
	sp_db_entry_t *entry;

	/* Attempt to find appropriate SA for each SP */
	for (entry = sp_db->list; NULL != entry; entry = entry->next) {
		sa_db_entry_t *cipher_sa = NULL;
		sa_db_entry_t *auth_sa = NULL;

		if (entry->esp)
			cipher_sa = find_sa_db_entry(&entry->src_subnet,
						     &entry->dst_subnet,
						     1);
		if (entry->ah)
			auth_sa = find_sa_db_entry(&entry->src_subnet,
						   &entry->dst_subnet,
						   0);

		if (cipher_sa || auth_sa)
			create_ipsec_cache_entry(cipher_sa,
						 auth_sa,
						 api_mode,
						 entry->input);
		else {
			printf(" WARNING: SA not found for SP\n");
			dump_sp_db_entry(entry);
		}
	}
}

/**
 * Initialize loopback
 *
 * Initialize ODP queues to create our own idea of loopbacks, which allow
 * testing without physical interfaces.  Interface name string will be of
 * the format "loopX" where X is the decimal number of the interface.
 *
 * @param intf     Loopback interface name string
 */
static
void initialize_loop(char *intf)
{
	int idx;
	loopback_db_entry_t *entry;
	odp_queue_t outq_def;
	odp_queue_t inq_def;
	char queue_name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	char mac_str[32];

	/* Derive loopback interface index */
	idx = loop_if_index(intf);
	if (idx < 0) {
		ODP_ERR("Error: loopback \"%s\" invalid\n", intf);
		exit(EXIT_FAILURE);
	}
	entry = &loopback_db->intf[idx];

	/* Dummy MAC address */
	memset(entry->mac, (0xF0 | idx), sizeof(entry->mac));

	/* Create input queue */
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
	snprintf(queue_name, sizeof(queue_name), "%i-loop_inq_def", idx);
	queue_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	inq_def = QUEUE_CREATE(queue_name, ODP_QUEUE_TYPE_SCHED, &qparam);
	if (inq_def == ODP_QUEUE_INVALID) {
		ODP_ERR("Error: input queue creation failed for %s\n", intf);
		exit(EXIT_FAILURE);
	}
	entry->inq_def = inq_def;

	/* Create output queue */
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
	snprintf(queue_name, sizeof(queue_name), "%i-loop_outq_def", idx);
	queue_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	outq_def = QUEUE_CREATE(queue_name, ODP_QUEUE_TYPE_POLL, &qparam);
	if (outq_def == ODP_QUEUE_INVALID) {
		ODP_ERR("Error: output queue creation failed for %s\n", intf);
		exit(EXIT_FAILURE);
	}
	entry->outq_def = outq_def;

	printf("Created loop:%02i, queue mode (ATOMIC queues)\n"
	       "          default loop%02i-INPUT queue:%u\n"
	       "          default loop%02i-OUTPUT queue:%u\n"
	       "          source mac address %s\n",
	       idx, idx, inq_def, idx, outq_def,
	       mac_addr_str(mac_str, entry->mac));

	/* Resolve any routes using this interface for output */
	resolve_fwd_db(intf, outq_def, entry->mac);
}

/**
 * Initialize interface
 *
 * Initialize ODP pktio and queues, query MAC address and update
 * forwarding database.
 *
 * @param intf     Interface name string
 * @param type     Packet IO type (BASIC, MMSG, MMAP)
 * @param fanout   Packet IO fanout
 */
static
void initialize_intf(char *intf, int type, int fanout)
{
	odp_buffer_pool_t pkt_pool;
	odp_pktio_t pktio;
	odp_queue_t outq_def;
	odp_queue_t inq_def;
	char inq_name[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	int ret;
	odp_pktio_params_t params;
	socket_params_t *sock_params = &params.sock_params;
	uint8_t src_mac[6];
	char src_mac_str[32];

	/* Lookup the packet pool */
	pkt_pool = odp_buffer_pool_lookup("packet_pool");
	if (pkt_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Error: pkt_pool not found\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Open a packet IO instance for thread and get default output queue
	 */
	sock_params->type = type;
	sock_params->fanout = fanout;
	pktio = odp_pktio_open(intf, pkt_pool, &params);
	if (pktio == ODP_PKTIO_INVALID) {
		ODP_ERR("Error: pktio create failed for %s\n", intf);
		exit(EXIT_FAILURE);
	}
	outq_def = odp_pktio_outq_getdef(pktio);

	/*
	 * Create and set the default INPUT queue associated with the 'pktio'
	 * resource
	 */
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_DEFAULT;
	snprintf(inq_name, sizeof(inq_name), "%i-pktio_inq_def", (int)pktio);
	inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	inq_def = QUEUE_CREATE(inq_name, ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (inq_def == ODP_QUEUE_INVALID) {
		ODP_ERR("Error: pktio queue creation failed for %s\n", intf);
		exit(EXIT_FAILURE);
	}

	ret = odp_pktio_inq_setdef(pktio, inq_def);
	if (ret != 0) {
		ODP_ERR("Error: default input-Q setup for %s\n", intf);
		exit(EXIT_FAILURE);
	}

	/* read the source MAC address for this interface */
	query_mac_address(intf, src_mac);

	printf("Created pktio:%02i, queue mode (ATOMIC queues)\n"
	       "          default pktio%02i-INPUT queue:%u\n"
	       "          source mac address %s\n",
	       pktio, pktio, inq_def, mac_addr_str(src_mac_str, src_mac));

	/* Resolve any routes using this interface for output */
	resolve_fwd_db(intf, outq_def, src_mac);
}

/**
 * Verify crypto operation completed successfully
 *
 * @param status  Pointer to cryto completion structure
 *
 * @return TRUE if all OK else FALSE
 */
static
boolean is_crypto_compl_status_ok(odp_crypto_compl_status_t *status)
{
	if (status->alg_err != ODP_CRYPTO_ALG_ERR_NONE)
		return FALSE;
	if (status->hw_err != ODP_CRYPTO_HW_ERR_NONE)
		return FALSE;
	return TRUE;
}

/**
 * Packet Processing - Input verification
 *
 * @param pkt  Packet to inspect
 * @param ctx  Packet process context (not used)
 *
 * @return PKT_CONTINUE if good, supported packet else PKT_DROP
 */
static
pkt_disposition_e input_verify(odp_packet_t pkt, pkt_ctx_t *ctx ODP_UNUSED)
{
	if (odp_unlikely(odp_packet_error(pkt)))
		return PKT_DROP;

	/*
	 * TODO: for stream packets figure out how to set these flags
	 *
	 * if (!odp_packet_inflag_eth(pkt))
	 *	return PKT_DROP;
	 *
	 * if (!odp_packet_inflag_ipv4(pkt))
	 *	return PKT_DROP;
	 */

	return PKT_CONTINUE;
}

/**
 * Packet Processing - Route lookup in forwarding database
 *
 * @param pkt  Packet to route
 * @param ctx  Packet process context
 *
 * @return PKT_CONTINUE if route found else PKT_DROP
 */
static
pkt_disposition_e route_fwd_db(odp_packet_t pkt, pkt_ctx_t *ctx)
{
	odp_ipv4hdr_t *ip = (odp_ipv4hdr_t *)odp_packet_l3(pkt);
	fwd_db_entry_t *entry;

	entry = find_fwd_db_entry(odp_be_to_cpu_32(ip->dst_addr));

	if (entry) {
		odp_ethhdr_t *eth = (odp_ethhdr_t *)odp_packet_l2(pkt);

		memcpy(&eth->dst, entry->dst_mac, 6);
		memcpy(&eth->src, entry->src_mac, 6);
		ctx->outq = entry->queue;

		return PKT_CONTINUE;
	}

	return PKT_DROP;
}

/**
 * Packet Processing - Input IPsec packet classification
 *
 * Verify the received packet has IPsec headers and a match
 * in the IPsec cache, if so issue crypto request else skip
 * input crypto.
 *
 * @param pkt   Packet to classify
 * @param ctx   Packet process context
 * @param skip  Pointer to return "skip" indication
 *
 * @return PKT_CONTINUE if done else PKT_POSTED
 */
static
pkt_disposition_e do_ipsec_in_classify(odp_packet_t pkt,
				       pkt_ctx_t *ctx,
				       boolean *skip)
{
	uint8_t *buf = odp_packet_buf_addr(pkt);
	odp_ipv4hdr_t *ip = (odp_ipv4hdr_t *)odp_packet_l3(pkt);
	int hdr_len;
	odp_ahhdr_t *ah = NULL;
	odp_esphdr_t *esp = NULL;
	ipsec_cache_entry_t *entry;
	odp_crypto_op_params_t params;
	bool posted = 0;

	/* Default to skip IPsec */
	*skip = TRUE;

	/* Check IP header for IPSec protocols and look it up */
	hdr_len = locate_ipsec_headers(ip, &ah, &esp);
	if (!ah && !esp)
		return PKT_CONTINUE;
	entry = find_ipsec_cache_entry_in(odp_be_to_cpu_32(ip->src_addr),
					  odp_be_to_cpu_32(ip->dst_addr),
					  ah,
					  esp);
	if (!entry)
		return PKT_CONTINUE;

	/* Account for configured ESP IV length in packet */
	hdr_len += entry->esp.iv_len;

	/* Initialize parameters block */
	memset(&params, 0, sizeof(params));
	params.session = entry->state.session;
	params.pkt = pkt;
	params.out_pkt = entry->in_place ? pkt : ODP_PACKET_INVALID;

	/*Save everything to context */
	ctx->ipsec.ip_tos = ip->tos;
	ctx->ipsec.ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
	ctx->ipsec.ip_ttl = ip->ttl;
	ctx->ipsec.ah_offset = ah ? ((uint8_t *)ah) - buf : 0;
	ctx->ipsec.esp_offset = esp ? ((uint8_t *)esp) - buf : 0;
	ctx->ipsec.hdr_len = hdr_len;
	ctx->ipsec.trl_len = 0;

	/*If authenticating, zero the mutable fields build the request */
	if (ah) {
		ip->chksum = 0;
		ip->tos = 0;
		ip->frag_offset = 0;
		ip->ttl = 0;

		params.auth_range.offset = ((uint8_t *)ip) - buf;
		params.auth_range.length = odp_be_to_cpu_16(ip->tot_len);
		params.hash_result_offset = ah->icv - buf;
	}

	/* If deciphering build request */
	if (esp) {
		params.cipher_range.offset = ipv4_data_p(ip) + hdr_len - buf;
		params.cipher_range.length = ipv4_data_len(ip) - hdr_len;
		params.override_iv_ptr = esp->iv;
	}

	/* Issue crypto request */
	*skip = FALSE;
	if (odp_crypto_operation(&params,
				 &posted,
				 odp_buffer_from_packet(pkt))) {
		abort();
	}
	return (posted) ? PKT_POSTED : PKT_CONTINUE;
}

/**
 * Packet Processing - Input IPsec packet processing cleanup
 *
 * @param pkt  Packet to handle
 * @param ctx  Packet process context
 *
 * @return PKT_CONTINUE if successful else PKT_DROP
 */
static
pkt_disposition_e do_ipsec_in_finish(odp_packet_t pkt,
				     pkt_ctx_t *ctx)
{
	odp_buffer_t event;
	odp_crypto_compl_status_t cipher_rc, auth_rc;
	odp_ipv4hdr_t *ip = (odp_ipv4hdr_t *)odp_packet_l3(pkt);
	int       hdr_len = ctx->ipsec.hdr_len;
	int       trl_len = 0;

	/* Check crypto result */
	event = odp_buffer_from_packet(pkt);
	odp_crypto_get_operation_compl_status(event, &cipher_rc, &auth_rc);
	if (!is_crypto_compl_status_ok(&cipher_rc))
		return PKT_DROP;
	if (!is_crypto_compl_status_ok(&auth_rc))
		return PKT_DROP;

	/*
	 * Finish auth
	 */
	if (ctx->ipsec.ah_offset) {
		uint8_t *buf = odp_packet_buf_addr(pkt);
		odp_ahhdr_t *ah;

		ah = (odp_ahhdr_t *)(ctx->ipsec.ah_offset + buf);
		ip->proto = ah->next_header;
	}

	/*
	 * Finish cipher by finding ESP trailer and processing
	 *
	 * NOTE: ESP authentication ICV not supported
	 */
	if (ctx->ipsec.esp_offset) {
		uint8_t *eop = (uint8_t *)(ip) + odp_be_to_cpu_16(ip->tot_len);
		odp_esptrl_t *esp_t = (odp_esptrl_t *)(eop) - 1;

		ip->proto = esp_t->next_header;
		trl_len += esp_t->pad_len + sizeof(*esp_t);
	}

	/* Finalize the IPv4 header */
	ipv4_adjust_len(ip, -(hdr_len + trl_len));
	ip->ttl = ctx->ipsec.ip_ttl;
	ip->tos = ctx->ipsec.ip_tos;
	ip->frag_offset = odp_cpu_to_be_16(ctx->ipsec.ip_frag_offset);
	ip->chksum = 0;
	odp_ipv4_csum_update(pkt);

	/* Correct the packet length and move payload into position */
	odp_packet_set_len(pkt, odp_packet_get_len(pkt) - (hdr_len + trl_len));
	memmove(ipv4_data_p(ip),
		ipv4_data_p(ip) + hdr_len,
		odp_be_to_cpu_16(ip->tot_len));

	/* Fall through to next state */
	return PKT_CONTINUE;
}

/**
 * Packet Processing - Output IPsec packet classification
 *
 * Verify the outbound packet has a match in the IPsec cache,
 * if so issue prepend IPsec headers and prepare parameters
 * for crypto API call.  Post the packet to ATOMIC queue so
 * that sequence numbers can be applied in packet order as
 * the next processing step.
 *
 * @param pkt   Packet to classify
 * @param ctx   Packet process context
 * @param skip  Pointer to return "skip" indication
 *
 * @return PKT_CONTINUE if done else PKT_POSTED
 */
static
pkt_disposition_e do_ipsec_out_classify(odp_packet_t pkt,
					pkt_ctx_t *ctx,
					boolean *skip)
{
	uint8_t *buf = odp_packet_buf_addr(pkt);
	odp_ipv4hdr_t *ip = (odp_ipv4hdr_t *)odp_packet_l3(pkt);
	uint16_t ip_data_len = ipv4_data_len(ip);
	uint8_t *ip_data = ipv4_data_p(ip);
	ipsec_cache_entry_t *entry;
	odp_crypto_op_params_t params;
	int      hdr_len = 0;
	int      trl_len = 0;
	odp_ahhdr_t *ah = NULL;
	odp_esphdr_t *esp = NULL;

	/* Default to skip IPsec */
	*skip = TRUE;

	/* Find record */
	entry = find_ipsec_cache_entry_out(odp_be_to_cpu_32(ip->src_addr),
					   odp_be_to_cpu_32(ip->dst_addr),
					   ip->proto);
	if (!entry)
		return PKT_CONTINUE;

	/* Save IPv4 stuff */
	ctx->ipsec.ip_tos = ip->tos;
	ctx->ipsec.ip_frag_offset = odp_be_to_cpu_16(ip->frag_offset);
	ctx->ipsec.ip_ttl = ip->ttl;

	/* Initialize parameters block */
	memset(&params, 0, sizeof(params));
	params.session = entry->state.session;
	params.pkt = pkt;
	params.out_pkt = entry->in_place ? pkt : ODP_PACKET_INVALID;

	/* Compute ah and esp, determine length of headers, move the data */
	if (entry->ah.alg) {
		ah = (odp_ahhdr_t *)(ip_data);
		hdr_len += sizeof(odp_ahhdr_t);
		hdr_len += entry->ah.icv_len;
	}
	if (entry->esp.alg) {
		esp = (odp_esphdr_t *)(ip_data + hdr_len);
		hdr_len += sizeof(odp_esphdr_t);
		hdr_len += entry->esp.iv_len;
	}
	memmove(ip_data + hdr_len, ip_data, ip_data_len);
	ip_data += hdr_len;

	/* For cipher, compute encrypt length, build headers and request */
	if (esp) {
		uint32_t encrypt_len;
		odp_esptrl_t *esp_t;

		encrypt_len = ESP_ENCODE_LEN(ip_data_len + sizeof(*esp_t),
					     entry->esp.block_len);
		trl_len = encrypt_len - ip_data_len;

		esp->spi = odp_cpu_to_be_32(entry->esp.spi);
		memcpy(esp + 1, entry->state.iv, entry->esp.iv_len);

		esp_t = (odp_esptrl_t *)(ip_data + encrypt_len) - 1;
		esp_t->pad_len     = trl_len - sizeof(*esp_t);
		esp_t->next_header = ip->proto;
		ip->proto = ODP_IPPROTO_ESP;

		params.cipher_range.offset = ip_data - buf;
		params.cipher_range.length = encrypt_len;
	}

	/* For authentication, build header clear mutables and build request */
	if (ah) {
		memset(ah, 0, sizeof(*ah) + entry->ah.icv_len);
		ah->spi = odp_cpu_to_be_32(entry->ah.spi);
		ah->ah_len = 1 + (entry->ah.icv_len / 4);
		ah->next_header = ip->proto;
		ip->proto = ODP_IPPROTO_AH;

		ip->chksum = 0;
		ip->tos = 0;
		ip->frag_offset = 0;
		ip->ttl = 0;

		params.auth_range.offset = ((uint8_t *)ip) - buf;
		params.auth_range.length =
			odp_be_to_cpu_16(ip->tot_len) + (hdr_len + trl_len);
		params.hash_result_offset = ah->icv - buf;
	}

	/* Set IPv4 length before authentication */
	ipv4_adjust_len(ip, hdr_len + trl_len);
	odp_packet_set_len(pkt, odp_packet_get_len(pkt) + (hdr_len + trl_len));

	/* Save remaining context */
	ctx->ipsec.hdr_len = hdr_len;
	ctx->ipsec.trl_len = trl_len;
	ctx->ipsec.ah_offset = ah ? ((uint8_t *)ah) - buf : 0;
	ctx->ipsec.esp_offset = esp ? ((uint8_t *)esp) - buf : 0;
	ctx->ipsec.ah_seq = &entry->state.ah_seq;
	ctx->ipsec.esp_seq = &entry->state.esp_seq;
	memcpy(&ctx->ipsec.params, &params, sizeof(params));

	/* Send packet to the atmoic queue to assign sequence numbers */
	*skip = FALSE;
	odp_queue_enq(seqnumq, odp_buffer_from_packet(pkt));

	return PKT_POSTED;
}

/**
 * Packet Processing - Output IPsec packet sequence number assignment
 *
 * Assign the necessary sequence numbers and then issue the crypto API call
 *
 * @param pkt  Packet to handle
 * @param ctx  Packet process context
 *
 * @return PKT_CONTINUE if done else PKT_POSTED
 */
static
pkt_disposition_e do_ipsec_out_seq(odp_packet_t pkt,
				   pkt_ctx_t *ctx)
{
	uint8_t *buf = odp_packet_buf_addr(pkt);
	bool posted = 0;

	/* We were dispatched from atomic queue, assign sequence numbers */
	if (ctx->ipsec.ah_offset) {
		odp_ahhdr_t *ah;

		ah = (odp_ahhdr_t *)(ctx->ipsec.ah_offset + buf);
		ah->seq_no = odp_cpu_to_be_32((*ctx->ipsec.ah_seq)++);
	}
	if (ctx->ipsec.esp_offset) {
		odp_esphdr_t *esp;

		esp = (odp_esphdr_t *)(ctx->ipsec.esp_offset + buf);
		esp->seq_no = odp_cpu_to_be_32((*ctx->ipsec.esp_seq)++);
	}

	/* Issue crypto request */
	if (odp_crypto_operation(&ctx->ipsec.params,
				 &posted,
				 odp_buffer_from_packet(pkt))) {
		abort();
	}
	return (posted) ? PKT_POSTED : PKT_CONTINUE;
}

/**
 * Packet Processing - Output IPsec packet processing cleanup
 *
 * @param pkt  Packet to handle
 * @param ctx  Packet process context
 *
 * @return PKT_CONTINUE if successful else PKT_DROP
 */
static
pkt_disposition_e do_ipsec_out_finish(odp_packet_t pkt,
				      pkt_ctx_t *ctx)
{
	odp_buffer_t event;
	odp_crypto_compl_status_t cipher_rc, auth_rc;
	odp_ipv4hdr_t *ip = (odp_ipv4hdr_t *)odp_packet_l3(pkt);

	/* Check crypto result */
	event = odp_buffer_from_packet(pkt);
	odp_crypto_get_operation_compl_status(event, &cipher_rc, &auth_rc);
	if (!is_crypto_compl_status_ok(&cipher_rc))
		return PKT_DROP;
	if (!is_crypto_compl_status_ok(&auth_rc))
		return PKT_DROP;

	/* Finalize the IPv4 header */
	ip->ttl = ctx->ipsec.ip_ttl;
	ip->tos = ctx->ipsec.ip_tos;
	ip->frag_offset = odp_cpu_to_be_16(ctx->ipsec.ip_frag_offset);
	ip->chksum = 0;
	odp_ipv4_csum_update(pkt);

	/* Fall through to next state */
	return PKT_CONTINUE;
}

/**
 * Packet IO worker thread
 *
 * Loop calling odp_schedule to obtain packets from one of three sources,
 * and continue processing the packet based on the state stored in its
 * per packet context.
 *
 *  - Input interfaces (i.e. new work)
 *  - Sequence number assignment queue
 *  - Per packet crypto API completion queue
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 *
 * @return NULL (should never return)
 */
static
void *pktio_thread(void *arg ODP_UNUSED)
{
	int thr;
	odp_packet_t pkt;
	odp_buffer_t buf;
	unsigned long pkt_cnt = 0;

	thr = odp_thread_id();

	printf("Pktio thread [%02i] starts\n", thr);

	odp_barrier_sync(&sync_barrier);

	/* Loop packets */
	for (;;) {
		pkt_disposition_e rc;
		pkt_ctx_t   *ctx;
		odp_queue_t  dispatchq;

		/* Use schedule to get buf from any input queue */
		buf = SCHEDULE(&dispatchq, ODP_SCHED_WAIT);
		pkt = odp_packet_from_buffer(buf);

		/* Determine new work versus completion or sequence number */
		if ((completionq != dispatchq) && (seqnumq != dispatchq)) {
			ctx = alloc_pkt_ctx(pkt);
			ctx->state = PKT_STATE_INPUT_VERIFY;
		} else {
			ctx = get_pkt_ctx_from_pkt(pkt);
		}

		/*
		 * We now have a packet and its associated context. Loop here
		 * executing processing based on the current state value stored
		 * in the context as long as the processing return code
		 * indicates PKT_CONTINUE.
		 *
		 * For other return codes:
		 *
		 *  o PKT_DONE   - finished with the packet
		 *  o PKT_DROP   - something incorrect about the packet, drop it
		 *  o PKT_POSTED - packet/event has been queued for later
		 */
		do {
			boolean skip = FALSE;

			switch (ctx->state) {
			case PKT_STATE_INPUT_VERIFY:

				rc = input_verify(pkt, ctx);
				ctx->state = PKT_STATE_IPSEC_IN_CLASSIFY;
				break;

			case PKT_STATE_IPSEC_IN_CLASSIFY:

				rc = do_ipsec_in_classify(pkt, ctx, &skip);
				ctx->state = (skip) ?
					PKT_STATE_ROUTE_LOOKUP :
					PKT_STATE_IPSEC_IN_FINISH;
				break;

			case PKT_STATE_IPSEC_IN_FINISH:

				rc = do_ipsec_in_finish(pkt, ctx);
				ctx->state = PKT_STATE_ROUTE_LOOKUP;
				break;

			case PKT_STATE_ROUTE_LOOKUP:

				rc = route_fwd_db(pkt, ctx);
				ctx->state = PKT_STATE_IPSEC_OUT_CLASSIFY;
				break;

			case PKT_STATE_IPSEC_OUT_CLASSIFY:

				rc = do_ipsec_out_classify(pkt, ctx, &skip);
				ctx->state = (skip) ?
					PKT_STATE_TRANSMIT :
					PKT_STATE_IPSEC_OUT_SEQ;
				break;

			case PKT_STATE_IPSEC_OUT_SEQ:

				rc = do_ipsec_out_seq(pkt, ctx);
				ctx->state = PKT_STATE_IPSEC_OUT_FINISH;
				break;

			case PKT_STATE_IPSEC_OUT_FINISH:

				rc = do_ipsec_out_finish(pkt, ctx);
				ctx->state = PKT_STATE_TRANSMIT;
				break;

			case PKT_STATE_TRANSMIT:

				odp_queue_enq(ctx->outq, buf);
				rc = PKT_DONE;
				break;

			default:
				rc = PKT_DROP;
				break;
			}
		} while (PKT_CONTINUE == rc);

		/* Free context on drop or transmit */
		if ((PKT_DROP == rc) || (PKT_DONE == rc))
			free_pkt_ctx(ctx);


		/* Check for drop */
		if (PKT_DROP == rc)
			odp_packet_free(pkt);

		/* Print packet counts every once in a while */
		if (PKT_DONE == rc) {
			if (odp_unlikely(pkt_cnt++ % 1000 == 0)) {
				printf("  [%02i] pkt_cnt:%lu\n", thr, pkt_cnt);
				fflush(NULL);
			}
		}
	}

	/* unreachable */
	return NULL;
}

/**
 * ODP ipsec example main function
 */
int
main(int argc, char *argv[])
{
	odp_linux_pthread_t thread_tbl[MAX_WORKERS];
	odp_buffer_pool_t pool;
	int thr_id;
	int num_workers;
	void *pool_base;
	int i;
	int first_core;
	int core_count;
	int stream_count;

	/* Init ODP before calling anything else */
	if (odp_init_global()) {
		ODP_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_crypto_init(32);

	/* Reserve memory for args from shared mem */
	args = odp_shm_reserve("shm_args", sizeof(args_t), ODP_CACHE_LINE_SIZE);
	if (args == NULL) {
		ODP_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(args, 0, sizeof(*args));

	/* Must init our databases before parsing args */
	ipsec_init_pre();
	init_fwd_db();
	init_loopback_db();
	init_stream_db();

	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	core_count  = odp_sys_core_count();
	num_workers = core_count;

	if (args->appl.core_count)
		num_workers = args->appl.core_count;

	if (num_workers > MAX_WORKERS)
		num_workers = MAX_WORKERS;

	printf("Num worker threads: %i\n", num_workers);

	/* Create a barrier to synchronize thread startup */
	odp_barrier_init_count(&sync_barrier, num_workers);

	/*
	 * By default core #0 runs Linux kernel background tasks.
	 * Start mapping thread from core #1
	 */
	first_core = (core_count == 1) ? 0 : 1;
	printf("First core:         %i\n\n", first_core);

	/* Init this thread */
	thr_id = odp_thread_create(0);
	odp_init_local(thr_id);

	/* Create packet buffer pool */
	pool_base = odp_shm_reserve("shm_packet_pool",
				    SHM_PKT_POOL_SIZE, ODP_CACHE_LINE_SIZE);
	if (pool_base == NULL) {
		ODP_ERR("Error: packet pool mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	pool = odp_buffer_pool_create("packet_pool", pool_base,
				      SHM_PKT_POOL_SIZE,
				      SHM_PKT_POOL_BUF_SIZE,
				      ODP_CACHE_LINE_SIZE,
				      ODP_BUFFER_TYPE_PACKET);
	if (pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Create context buffer pool */
	pool_base = odp_shm_reserve("shm_ctx_pool",
				    SHM_CTX_POOL_SIZE, ODP_CACHE_LINE_SIZE);
	if (pool_base == NULL) {
		ODP_ERR("Error: context pool mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	ctx_pool = odp_buffer_pool_create("ctx_pool", pool_base,
					  SHM_CTX_POOL_SIZE,
					  SHM_CTX_POOL_BUF_SIZE,
					  ODP_CACHE_LINE_SIZE,
					  ODP_BUFFER_TYPE_RAW);
	if (ctx_pool == ODP_BUFFER_POOL_INVALID) {
		ODP_ERR("Error: context pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Populate our IPsec cache */
	printf("Using %s mode for crypto API\n\n",
	       (CRYPTO_API_SYNC == args->appl.mode) ? "SYNC" :
	       (CRYPTO_API_ASYNC_IN_PLACE == args->appl.mode) ?
	       "ASYNC_IN_PLACE" : "ASYNC_NEW_BUFFER");
	ipsec_init_post(args->appl.mode);

	/* Initialize interfaces (which resolves FWD DB entries */
	for (i = 0; i < args->appl.if_count; i++) {
		if (!strncmp("loop", args->appl.if_names[i], strlen("loop")))
			initialize_loop(args->appl.if_names[i]);
		else
			initialize_intf(args->appl.if_names[i],
					args->appl.type,
					args->appl.fanout);
	}

	/* If we have test streams build them before starting workers */
	resolve_stream_db();
	stream_count = create_stream_db_inputs();

	/*
	 * Create and init worker threads
	 */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	for (i = 0; i < num_workers; ++i) {
		int core;

		core = (first_core + i) % core_count;

		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments.
		 * Calls odp_thread_create(cpu) for each thread
		 */
		odp_linux_pthread_create(thread_tbl, 1, core, pktio_thread,
					 &args->thread[i]);
	}

	/*
	 * If there are streams attempt to verify them else
	 * wait indefinitely
	 */
	if (stream_count) {
		boolean done;

		do {
			done = verify_stream_db_outputs();
			sleep(1);
		} while (!done);
		printf("All received\n");
	} else {
		odp_linux_pthread_join(thread_tbl, num_workers);
	}

	printf("Exit\n\n");

	return 0;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *names, *str, *token, *save;
	size_t len;
	int i;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"route", required_argument, NULL, 'r'},	/* return 'r' */
		{"policy", required_argument, NULL, 'p'},	/* return 'p' */
		{"ah", required_argument, NULL, 'a'},	        /* return 'a' */
		{"esp", required_argument, NULL, 'e'},	        /* return 'e' */
		{"stream", required_argument, NULL, 's'},	/* return 's' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->type = 3;  /* 3: ODP_PKTIO_TYPE_SOCKET_MMAP */
	appl_args->fanout = 0; /* turn off fanout by default for mmap */
	appl_args->mode = 0;  /* turn off async crypto API by default */

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:m:t:f:h:r:p:a:e:s:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->core_count = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
			}
			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
				calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
				appl_args->if_names[i] = token;
			}
			break;

		case 't':
			appl_args->type = atoi(optarg);
			break;

		case 'f':
			appl_args->fanout = atoi(optarg);
			break;

		case 'm':
			appl_args->mode = atoi(optarg);
			break;

		case 'r':
			create_fwd_db_entry(optarg);
			break;

		case 'p':
			create_sp_db_entry(optarg);
			break;

		case 'a':
			create_sa_db_entry(optarg, FALSE);
			break;

		case 'e':
			create_sa_db_entry(optarg, TRUE);
			break;

		case 's':
			create_stream_db_entry(optarg);
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %"PRIu64"\n"
	       "Cache line size: %i\n"
	       "Core count:      %i\n"
	       "\n",
	       odp_version_api_str(), odp_sys_cpu_model_str(), odp_sys_cpu_hz(),
	       odp_sys_cache_line_size(), odp_sys_core_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);

	printf("\n");

	dump_fwd_db();
	dump_sp_db();
	dump_sa_db();
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth1,eth2,eth3 -m 0\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       " -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       " -t, --type   1: ODP_PKTIO_TYPE_SOCKET_BASIC\n"
	       "              2: ODP_PKTIO_TYPE_SOCKET_MMSG\n"
	       "              3: ODP_PKTIO_TYPE_SOCKET_MMAP\n"
	       "              4: ODP_PKTIO_TYPE_NETMAP\n"
	       "	 Default: 3: ODP_PKTIO_TYPE_SOCKET_MMAP\n"
	       " -f, --fanout 0: off 1: on (Default 1: on)\n"
	       " -m, --mode   0: SYNC\n"
	       "              1: ASYNC_IN_PLACE\n"
	       "              2: ASYNC_NEW_BUFFER\n"
	       "         Default: 0: SYNC api mode\n"
	       "\n"
	       "Routing / IPSec OPTIONS:\n"
	       " -r, --route SubNet:Intf:NextHopMAC\n"
	       " -p, --policy SrcSubNet:DstSubNet:(in|out):(ah|esp|both)\n"
	       " -e, --esp SrcIP:DstIP:(3des|null):SPI:Key192\n"
	       " -a, --ah SrcIP:DstIP:(md5|null):SPI:Key128\n"
	       "\n"
	       "  Where: NextHopMAC is raw hex/dot notation, i.e. 03.BA.44.9A.CE.02\n"
	       "         IP is decimal/dot notation, i.e. 192.168.1.1\n"
	       "         SubNet is decimal/dot/slash notation, i.e 192.168.0.0/16\n"
	       "         SPI is raw hex, 32 bits\n"
	       "         KeyXXX is raw hex, XXX bits long\n"
	       "\n"
	       "  Examples:\n"
	       "     -r 192.168.222.0/24:p8p1:08.00.27.F5.8B.DB\n"
	       "     -p 192.168.111.0/24:192.168.222.0/24:out:esp\n"
	       "     -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224\n"
	       "     -a 192.168.111.2:192.168.222.2:md5:201:a731649644c5dee92cbd9c2e7e188ee6\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -c, --count <number> Core count.\n"
	       "  -h, --help           Display help and exit.\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
		);
}
