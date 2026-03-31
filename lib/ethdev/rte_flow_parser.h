/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 * Copyright 2026 DynaNIC Semiconductors, Ltd.
 */

/**
 * @file
 * Flow Parser Library - Simple API
 *
 * Lightweight helpers for parsing testpmd-style flow rule strings into
 * standard rte_flow C structures. For the full command parser and cmdline
 * integration API, include rte_flow_parser_cmdline.h instead.
 */

#ifndef _RTE_FLOW_PARSER_H_
#define _RTE_FLOW_PARSER_H_

#include <stddef.h>
#include <stdint.h>

#include <rte_compat.h>
#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Shared limits used across parser helpers. */
#define ACTION_RAW_ENCAP_MAX_DATA 512
#define RAW_ENCAP_CONFS_MAX_NUM 8
#define ACTION_IPV6_EXT_PUSH_MAX_DATA 512
#define IPV6_EXT_PUSH_CONFS_MAX_NUM 8
#define ACTION_SAMPLE_ACTIONS_NUM 10
#define RAW_SAMPLE_CONFS_MAX_NUM 8
#define ACTION_RSS_QUEUE_NUM 128
#define ACTION_VXLAN_ENCAP_ITEMS_NUM 6
#define ACTION_NVGRE_ENCAP_ITEMS_NUM 5

struct rte_flow_parser_vxlan_encap_conf {
	uint32_t select_ipv4:1;
	uint32_t select_vlan:1;
	uint32_t select_tos_ttl:1;
	uint8_t vni[3];
	rte_be16_t udp_src;
	rte_be16_t udp_dst;
	rte_be32_t ipv4_src;
	rte_be32_t ipv4_dst;
	struct rte_ipv6_addr ipv6_src;
	struct rte_ipv6_addr ipv6_dst;
	rte_be16_t vlan_tci;
	uint8_t ip_tos;
	uint8_t ip_ttl;
	struct rte_ether_addr eth_src;
	struct rte_ether_addr eth_dst;
};

struct rte_flow_parser_nvgre_encap_conf {
	uint32_t select_ipv4:1;
	uint32_t select_vlan:1;
	uint8_t tni[3];
	rte_be32_t ipv4_src;
	rte_be32_t ipv4_dst;
	struct rte_ipv6_addr ipv6_src;
	struct rte_ipv6_addr ipv6_dst;
	rte_be16_t vlan_tci;
	struct rte_ether_addr eth_src;
	struct rte_ether_addr eth_dst;
};

struct rte_flow_parser_l2_encap_conf {
	uint32_t select_ipv4:1;
	uint32_t select_vlan:1;
	rte_be16_t vlan_tci;
	struct rte_ether_addr eth_src;
	struct rte_ether_addr eth_dst;
};

struct rte_flow_parser_l2_decap_conf {
	uint32_t select_vlan:1;
};

struct rte_flow_parser_mplsogre_encap_conf {
	uint32_t select_ipv4:1;
	uint32_t select_vlan:1;
	uint8_t label[3];
	rte_be32_t ipv4_src;
	rte_be32_t ipv4_dst;
	struct rte_ipv6_addr ipv6_src;
	struct rte_ipv6_addr ipv6_dst;
	rte_be16_t vlan_tci;
	uint8_t eth_src[RTE_ETHER_ADDR_LEN];
	uint8_t eth_dst[RTE_ETHER_ADDR_LEN];
};

struct rte_flow_parser_mplsogre_decap_conf {
	uint32_t select_ipv4:1;
	uint32_t select_vlan:1;
};

struct rte_flow_parser_mplsoudp_encap_conf {
	uint32_t select_ipv4:1;
	uint32_t select_vlan:1;
	uint8_t label[3];
	rte_be16_t udp_src;
	rte_be16_t udp_dst;
	rte_be32_t ipv4_src;
	rte_be32_t ipv4_dst;
	struct rte_ipv6_addr ipv6_src;
	struct rte_ipv6_addr ipv6_dst;
	rte_be16_t vlan_tci;
	uint8_t eth_src[RTE_ETHER_ADDR_LEN];
	uint8_t eth_dst[RTE_ETHER_ADDR_LEN];
};

struct rte_flow_parser_mplsoudp_decap_conf {
	uint32_t select_ipv4:1;
	uint32_t select_vlan:1;
};

/**
 * Parse flow attributes from a CLI snippet.
 *
 * Parses attribute strings as used inside a flow command, such as
 * "ingress", "egress", "ingress group 1 priority 5", or "transfer".
 *
 * @warning Not thread-safe. Uses internal static storage.
 *
 * @param src
 *   NUL-terminated attribute string.
 * @param[out] attr
 *   Output attributes structure filled on success.
 * @return
 *   0 on success or a negative errno-style value on error.
 */
__rte_experimental
int rte_flow_parser_parse_attr_str(const char *src, struct rte_flow_attr *attr);

/**
 * Parse a flow pattern from a CLI snippet.
 *
 * Parses pattern strings as used inside a flow command, such as
 * "eth / ipv4 src is 192.168.1.1 / tcp dst is 80 / end".
 *
 * @warning Not thread-safe. Uses internal static storage that is overwritten
 * on each call.
 *
 * @param src
 *   NUL-terminated pattern string.
 * @param[out] pattern
 *   Output pointer to the parsed pattern array. Points to internal storage
 *   valid until the next parse call on the same thread.
 * @param[out] pattern_n
 *   Number of entries in the pattern array.
 * @return
 *   0 on success or a negative errno-style value on error.
 */
__rte_experimental
int rte_flow_parser_parse_pattern_str(const char *src,
				      const struct rte_flow_item **pattern,
				      uint32_t *pattern_n);

/**
 * Parse flow actions from a CLI snippet.
 *
 * Parses action strings as used inside a flow command, such as
 * "queue index 5 / end", "mark id 42 / drop / end", or "count / rss / end".
 *
 * @warning Not thread-safe. Uses internal static storage that is overwritten
 * on each call.
 *
 * @param src
 *   NUL-terminated actions string.
 * @param[out] actions
 *   Output pointer to the parsed actions array. Points to internal storage
 *   valid until the next parse call on the same thread.
 * @param[out] actions_n
 *   Number of entries in the actions array.
 * @return
 *   0 on success or a negative errno-style value on error.
 */
__rte_experimental
int rte_flow_parser_parse_actions_str(const char *src,
				      const struct rte_flow_action **actions,
				      uint32_t *actions_n);

/**
 * Reset parser defaults and clear stored caches.
 *
 * @warning Not thread-safe.
 */
__rte_experimental
void rte_flow_parser_reset_defaults(void);

/**
 * @warning Not thread-safe. The returned pointer refers to global parser
 * state that may be modified by any subsequent parser API call.
 */
__rte_experimental
struct rte_flow_parser_vxlan_encap_conf *rte_flow_parser_vxlan_encap_conf(void);

/** @warning Not thread-safe. @see rte_flow_parser_vxlan_encap_conf */
__rte_experimental
struct rte_flow_parser_nvgre_encap_conf *rte_flow_parser_nvgre_encap_conf(void);

/** @warning Not thread-safe. @see rte_flow_parser_vxlan_encap_conf */
__rte_experimental
struct rte_flow_parser_l2_encap_conf *rte_flow_parser_l2_encap_conf(void);

/** @warning Not thread-safe. @see rte_flow_parser_vxlan_encap_conf */
__rte_experimental
struct rte_flow_parser_l2_decap_conf *rte_flow_parser_l2_decap_conf(void);

/** @warning Not thread-safe. @see rte_flow_parser_vxlan_encap_conf */
__rte_experimental
struct rte_flow_parser_mplsogre_encap_conf *rte_flow_parser_mplsogre_encap_conf(void);

/** @warning Not thread-safe. @see rte_flow_parser_vxlan_encap_conf */
__rte_experimental
struct rte_flow_parser_mplsogre_decap_conf *rte_flow_parser_mplsogre_decap_conf(void);

/** @warning Not thread-safe. @see rte_flow_parser_vxlan_encap_conf */
__rte_experimental
struct rte_flow_parser_mplsoudp_encap_conf *rte_flow_parser_mplsoudp_encap_conf(void);

/** @warning Not thread-safe. @see rte_flow_parser_vxlan_encap_conf */
__rte_experimental
struct rte_flow_parser_mplsoudp_decap_conf *rte_flow_parser_mplsoudp_decap_conf(void);

/**
 * Raw encap configuration accessor.
 *
 * @warning Not thread-safe.
 */
__rte_experimental
const struct rte_flow_action_raw_encap *rte_flow_parser_raw_encap_conf_get(uint16_t index);

/**
 * Raw decap configuration accessor.
 *
 * @warning Not thread-safe.
 */
__rte_experimental
const struct rte_flow_action_raw_decap *rte_flow_parser_raw_decap_conf_get(uint16_t index);

/**
 * Conntrack context accessor.
 *
 * @warning Not thread-safe.
 */
__rte_experimental
struct rte_flow_action_conntrack *rte_flow_parser_conntrack_context(void);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_FLOW_PARSER_H_ */
