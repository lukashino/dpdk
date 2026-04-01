/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Open vSwitch community
 */

/*
 * RTE flow pattern string parser.
 *
 * Uses the same token-based recursive-descent approach as testpmd's
 * cmdline_flow.c. The grammar (token tables and item arrays) is shared
 * between this library and testpmd via .inc files:
 *   - rte_flow_pattern_items.inc: item_*[] next-token arrays
 *   - rte_flow_pattern_tokens.inc: ITEM_* token_list entries
 *
 * Parse callbacks (parse_vc, parse_vc_spec, value parsers) are defined
 * here with the SAME names and signatures as in cmdline_flow.c.
 * Each compilation unit provides its own implementation; the .inc files
 * bind to whichever is visible. This means the grammar is defined once
 * but the buffer handling is context-specific.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include <limits.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_flow.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_sctp.h>
#include <rte_icmp.h>
#include <rte_vxlan.h>
#include <rte_gre.h>
#include <rte_mpls.h>
#include <rte_gtp.h>
#include <rte_geneve.h>
#include <rte_ecpri.h>
#include <rte_l2tpv2.h>
#include <rte_string_fns.h>
#include <eal_export.h>
#include <rte_bitops.h>

#include "rte_flow_pattern_parser.h"

/* ---- Constants ---- */

#define CTX_STACK_SIZE 16

#define ITEM_RAW_PATTERN_SIZE 512
#define ITEM_RAW_SIZE \
	(sizeof(struct rte_flow_item_raw) + ITEM_RAW_PATTERN_SIZE)

#define ITEM_GENEVE_OPT_DATA_SIZE 124
#define FLOW_FIELD_PATTERN_SIZE 32

/* Maximum buffer size for internal parsing. */
#define PP_BUFFER_SIZE 16384

/* ---- Internal token index enum ---- */

/*
 * Pattern-related token indices. Uses the SAME names as testpmd's
 * cmdline_flow.c so that the shared .inc files resolve correctly.
 * The numeric values differ from cmdline_flow.c (this is a compact
 * enum), but that's fine because each compilation unit uses its own
 * token_list array.
 */
enum index {
	/* Special tokens. */
	ZERO = 0,
	END,
	START_SET,
	END_SET,

	/* Common value tokens for pattern field parsing. */
	COMMON_INTEGER,
	COMMON_UNSIGNED,
	COMMON_PREFIX,
	COMMON_BOOLEAN,
	COMMON_STRING,
	COMMON_HEX,
	COMMON_FILE_PATH,
	COMMON_MAC_ADDR,
	COMMON_IPV4_ADDR,
	COMMON_IPV6_ADDR,

	COMMON_FLEX_HANDLE,
	COMMON_METER_COLOR_NAME,
	COMMON_POLICY_ID,
	COMMON_PORT_ID,

	/* Referenced by ITEM_END's .next and ITEM_POL_* entries. */
	ACTIONS,
	ACTION_POL_G,
	ACTION_POL_Y,
	ACTION_POL_R,

	/* Validate/create pattern. */
	ITEM_PATTERN,
	ITEM_PARAM_IS,
	ITEM_PARAM_SPEC,
	ITEM_PARAM_LAST,
	ITEM_PARAM_MASK,
	ITEM_PARAM_PREFIX,
	ITEM_NEXT,
	ITEM_END,
	ITEM_VOID,
	ITEM_INVERT,
	ITEM_ANY,
	ITEM_ANY_NUM,
	ITEM_PORT_ID,
	ITEM_PORT_ID_ID,
	ITEM_MARK,
	ITEM_MARK_ID,
	ITEM_RAW,
	ITEM_RAW_RELATIVE,
	ITEM_RAW_SEARCH,
	ITEM_RAW_OFFSET,
	ITEM_RAW_LIMIT,
	ITEM_RAW_PATTERN,
	ITEM_RAW_PATTERN_HEX,
	ITEM_ETH,
	ITEM_ETH_DST,
	ITEM_ETH_SRC,
	ITEM_ETH_TYPE,
	ITEM_ETH_HAS_VLAN,
	ITEM_VLAN,
	ITEM_VLAN_TCI,
	ITEM_VLAN_PCP,
	ITEM_VLAN_DEI,
	ITEM_VLAN_VID,
	ITEM_VLAN_INNER_TYPE,
	ITEM_VLAN_HAS_MORE_VLAN,
	ITEM_IPV4,
	ITEM_IPV4_VER_IHL,
	ITEM_IPV4_TOS,
	ITEM_IPV4_LENGTH,
	ITEM_IPV4_ID,
	ITEM_IPV4_FRAGMENT_OFFSET,
	ITEM_IPV4_TTL,
	ITEM_IPV4_PROTO,
	ITEM_IPV4_SRC,
	ITEM_IPV4_DST,
	ITEM_IPV6,
	ITEM_IPV6_TC,
	ITEM_IPV6_FLOW,
	ITEM_IPV6_LEN,
	ITEM_IPV6_PROTO,
	ITEM_IPV6_HOP,
	ITEM_IPV6_SRC,
	ITEM_IPV6_DST,
	ITEM_IPV6_HAS_FRAG_EXT,
	ITEM_IPV6_ROUTING_EXT,
	ITEM_IPV6_ROUTING_EXT_TYPE,
	ITEM_IPV6_ROUTING_EXT_NEXT_HDR,
	ITEM_IPV6_ROUTING_EXT_SEG_LEFT,
	ITEM_ICMP,
	ITEM_ICMP_TYPE,
	ITEM_ICMP_CODE,
	ITEM_ICMP_IDENT,
	ITEM_ICMP_SEQ,
	ITEM_UDP,
	ITEM_UDP_SRC,
	ITEM_UDP_DST,
	ITEM_TCP,
	ITEM_TCP_SRC,
	ITEM_TCP_DST,
	ITEM_TCP_FLAGS,
	ITEM_SCTP,
	ITEM_SCTP_SRC,
	ITEM_SCTP_DST,
	ITEM_SCTP_TAG,
	ITEM_SCTP_CKSUM,
	ITEM_VXLAN,
	ITEM_VXLAN_VNI,
	ITEM_VXLAN_FLAG_G,
	ITEM_VXLAN_FLAG_VER,
	ITEM_VXLAN_FLAG_I,
	ITEM_VXLAN_FLAG_P,
	ITEM_VXLAN_FLAG_B,
	ITEM_VXLAN_FLAG_O,
	ITEM_VXLAN_FLAG_D,
	ITEM_VXLAN_FLAG_A,
	ITEM_VXLAN_GBP_ID,
	ITEM_VXLAN_GPE_PROTO,
	ITEM_VXLAN_FIRST_RSVD,
	ITEM_VXLAN_SECND_RSVD,
	ITEM_VXLAN_THIRD_RSVD,
	ITEM_VXLAN_LAST_RSVD,
	ITEM_E_TAG,
	ITEM_E_TAG_GRP_ECID_B,
	ITEM_NVGRE,
	ITEM_NVGRE_TNI,
	ITEM_MPLS,
	ITEM_MPLS_LABEL,
	ITEM_MPLS_TC,
	ITEM_MPLS_S,
	ITEM_MPLS_TTL,
	ITEM_GRE,
	ITEM_GRE_PROTO,
	ITEM_GRE_C_RSVD0_VER,
	ITEM_GRE_C_BIT,
	ITEM_GRE_K_BIT,
	ITEM_GRE_S_BIT,
	ITEM_FUZZY,
	ITEM_FUZZY_THRESH,
	ITEM_GTP,
	ITEM_GTP_FLAGS,
	ITEM_GTP_MSG_TYPE,
	ITEM_GTP_TEID,
	ITEM_GTPC,
	ITEM_GTPU,
	ITEM_GENEVE,
	ITEM_GENEVE_VNI,
	ITEM_GENEVE_PROTO,
	ITEM_GENEVE_OPTLEN,
	ITEM_VXLAN_GPE,
	ITEM_VXLAN_GPE_VNI,
	ITEM_VXLAN_GPE_PROTO_IN_DEPRECATED_VXLAN_GPE_HDR,
	ITEM_VXLAN_GPE_FLAGS,
	ITEM_VXLAN_GPE_RSVD0,
	ITEM_VXLAN_GPE_RSVD1,
	ITEM_ARP_ETH_IPV4,
	ITEM_ARP_ETH_IPV4_SHA,
	ITEM_ARP_ETH_IPV4_SPA,
	ITEM_ARP_ETH_IPV4_THA,
	ITEM_ARP_ETH_IPV4_TPA,
	ITEM_IPV6_EXT,
	ITEM_IPV6_EXT_NEXT_HDR,
	ITEM_IPV6_FRAG_EXT,
	ITEM_IPV6_FRAG_EXT_NEXT_HDR,
	ITEM_IPV6_FRAG_EXT_FRAG_DATA,
	ITEM_IPV6_FRAG_EXT_ID,
	ITEM_ICMP6,
	ITEM_ICMP6_TYPE,
	ITEM_ICMP6_CODE,
	ITEM_ICMP6_ECHO_REQUEST,
	ITEM_ICMP6_ECHO_REQUEST_ID,
	ITEM_ICMP6_ECHO_REQUEST_SEQ,
	ITEM_ICMP6_ECHO_REPLY,
	ITEM_ICMP6_ECHO_REPLY_ID,
	ITEM_ICMP6_ECHO_REPLY_SEQ,
	ITEM_ICMP6_ND_NS,
	ITEM_ICMP6_ND_NS_TARGET_ADDR,
	ITEM_ICMP6_ND_NA,
	ITEM_ICMP6_ND_NA_TARGET_ADDR,
	ITEM_ICMP6_ND_OPT,
	ITEM_ICMP6_ND_OPT_TYPE,
	ITEM_ICMP6_ND_OPT_SLA_ETH,
	ITEM_ICMP6_ND_OPT_SLA_ETH_SLA,
	ITEM_ICMP6_ND_OPT_TLA_ETH,
	ITEM_ICMP6_ND_OPT_TLA_ETH_TLA,
	ITEM_META,
	ITEM_META_DATA,
	ITEM_RANDOM,
	ITEM_RANDOM_VALUE,
	ITEM_GRE_KEY,
	ITEM_GRE_KEY_VALUE,
	ITEM_GRE_OPTION,
	ITEM_GRE_OPTION_CHECKSUM,
	ITEM_GRE_OPTION_KEY,
	ITEM_GRE_OPTION_SEQUENCE,
	ITEM_GTP_PSC,
	ITEM_GTP_PSC_QFI,
	ITEM_GTP_PSC_PDU_T,
	ITEM_PPPOES,
	ITEM_PPPOED,
	ITEM_PPPOE_SEID,
	ITEM_PPPOE_PROTO_ID,
	ITEM_HIGIG2,
	ITEM_HIGIG2_CLASSIFICATION,
	ITEM_HIGIG2_VID,
	ITEM_TAG,
	ITEM_TAG_DATA,
	ITEM_TAG_INDEX,
	ITEM_L2TPV3OIP,
	ITEM_L2TPV3OIP_SESSION_ID,
	ITEM_ESP,
	ITEM_ESP_SPI,
	ITEM_AH,
	ITEM_AH_SPI,
	ITEM_PFCP,
	ITEM_PFCP_S_FIELD,
	ITEM_PFCP_SEID,
	ITEM_ECPRI,
	ITEM_ECPRI_COMMON,
	ITEM_ECPRI_COMMON_TYPE,
	ITEM_ECPRI_COMMON_TYPE_IQ_DATA,
	ITEM_ECPRI_COMMON_TYPE_RTC_CTRL,
	ITEM_ECPRI_COMMON_TYPE_DLY_MSR,
	ITEM_ECPRI_MSG_IQ_DATA_PCID,
	ITEM_ECPRI_MSG_RTC_CTRL_RTCID,
	ITEM_ECPRI_MSG_DLY_MSR_MSRID,
	ITEM_GENEVE_OPT,
	ITEM_GENEVE_OPT_CLASS,
	ITEM_GENEVE_OPT_TYPE,
	ITEM_GENEVE_OPT_LENGTH,
	ITEM_GENEVE_OPT_DATA,
	ITEM_INTEGRITY,
	ITEM_INTEGRITY_LEVEL,
	ITEM_INTEGRITY_VALUE,
	ITEM_CONNTRACK,
	ITEM_POL_PORT,
	ITEM_POL_METER,
	ITEM_POL_POLICY,
	ITEM_PORT_REPRESENTOR,
	ITEM_PORT_REPRESENTOR_PORT_ID,
	ITEM_REPRESENTED_PORT,
	ITEM_REPRESENTED_PORT_ETHDEV_PORT_ID,
	ITEM_FLEX,
	ITEM_FLEX_ITEM_HANDLE,
	ITEM_FLEX_PATTERN_HANDLE,
	ITEM_L2TPV2,
	ITEM_L2TPV2_TYPE,
	ITEM_L2TPV2_TYPE_DATA,
	ITEM_L2TPV2_TYPE_DATA_L,
	ITEM_L2TPV2_TYPE_DATA_S,
	ITEM_L2TPV2_TYPE_DATA_O,
	ITEM_L2TPV2_TYPE_DATA_L_S,
	ITEM_L2TPV2_TYPE_CTRL,
	ITEM_L2TPV2_MSG_DATA_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_SESSION_ID,
	ITEM_L2TPV2_MSG_DATA_L_LENGTH,
	ITEM_L2TPV2_MSG_DATA_L_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_L_SESSION_ID,
	ITEM_L2TPV2_MSG_DATA_S_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_S_SESSION_ID,
	ITEM_L2TPV2_MSG_DATA_S_NS,
	ITEM_L2TPV2_MSG_DATA_S_NR,
	ITEM_L2TPV2_MSG_DATA_O_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_O_SESSION_ID,
	ITEM_L2TPV2_MSG_DATA_O_OFFSET,
	ITEM_L2TPV2_MSG_DATA_L_S_LENGTH,
	ITEM_L2TPV2_MSG_DATA_L_S_TUNNEL_ID,
	ITEM_L2TPV2_MSG_DATA_L_S_SESSION_ID,
	ITEM_L2TPV2_MSG_DATA_L_S_NS,
	ITEM_L2TPV2_MSG_DATA_L_S_NR,
	ITEM_L2TPV2_MSG_CTRL_LENGTH,
	ITEM_L2TPV2_MSG_CTRL_TUNNEL_ID,
	ITEM_L2TPV2_MSG_CTRL_SESSION_ID,
	ITEM_L2TPV2_MSG_CTRL_NS,
	ITEM_L2TPV2_MSG_CTRL_NR,
	ITEM_PPP,
	ITEM_PPP_ADDR,
	ITEM_PPP_CTRL,
	ITEM_PPP_PROTO_ID,
	ITEM_METER,
	ITEM_METER_COLOR,
	ITEM_QUOTA,
	ITEM_QUOTA_STATE,
	ITEM_QUOTA_STATE_NAME,
	ITEM_AGGR_AFFINITY,
	ITEM_AGGR_AFFINITY_VALUE,
	ITEM_TX_QUEUE,
	ITEM_TX_QUEUE_VALUE,
	ITEM_IB_BTH,
	ITEM_IB_BTH_OPCODE,
	ITEM_IB_BTH_PKEY,
	ITEM_IB_BTH_DST_QPN,
	ITEM_IB_BTH_PSN,
	ITEM_IPV6_PUSH_REMOVE_EXT,
	ITEM_IPV6_PUSH_REMOVE_EXT_TYPE,
	ITEM_PTYPE,
	ITEM_PTYPE_VALUE,
	ITEM_NSH,
	ITEM_COMPARE,
	ITEM_COMPARE_OP,
	ITEM_COMPARE_OP_VALUE,
	ITEM_COMPARE_FIELD_A_TYPE,
	ITEM_COMPARE_FIELD_A_TYPE_VALUE,
	ITEM_COMPARE_FIELD_A_LEVEL,
	ITEM_COMPARE_FIELD_A_LEVEL_VALUE,
	ITEM_COMPARE_FIELD_A_TAG_INDEX,
	ITEM_COMPARE_FIELD_A_TYPE_ID,
	ITEM_COMPARE_FIELD_A_CLASS_ID,
	ITEM_COMPARE_FIELD_A_OFFSET,
	ITEM_COMPARE_FIELD_B_TYPE,
	ITEM_COMPARE_FIELD_B_TYPE_VALUE,
	ITEM_COMPARE_FIELD_B_LEVEL,
	ITEM_COMPARE_FIELD_B_LEVEL_VALUE,
	ITEM_COMPARE_FIELD_B_TAG_INDEX,
	ITEM_COMPARE_FIELD_B_TYPE_ID,
	ITEM_COMPARE_FIELD_B_CLASS_ID,
	ITEM_COMPARE_FIELD_B_OFFSET,
	ITEM_COMPARE_FIELD_B_VALUE,
	ITEM_COMPARE_FIELD_B_POINTER,
	ITEM_COMPARE_FIELD_WIDTH,

	PP_INDEX_MAX
};

/* ---- Internal types (mirrors cmdline_flow.c) ---- */

typedef uint16_t portid_t;

/** Parser context. */
struct context {
	const enum index *next[CTX_STACK_SIZE];
	const void *args[CTX_STACK_SIZE];
	enum index curr;
	enum index prev;
	int next_num;
	int args_num;
	uint32_t eol:1;
	uint32_t last:1;
	portid_t port;
	uint32_t objdata;
	void *object;
	void *objmask;
};

/** Token argument. */
struct arg {
	uint32_t hton:1;
	uint32_t sign:1;
	uint32_t bounded:1;
	uintmax_t min;
	uintmax_t max;
	uint32_t offset;
	uint32_t size;
	const uint8_t *mask;
};

/** Parser token definition. */
struct token {
	const char *type;
	const char *help;
	const void *priv;
	const enum index *const *next;
	const struct arg *const *args;
	int (*call)(struct context *ctx, const struct token *token,
		    const char *str, unsigned int len,
		    void *buf, unsigned int size);
	int (*comp)(struct context *ctx, const struct token *token,
		    unsigned int ent, char *buf, unsigned int size);
	const char *name;
};

/** Private data for pattern items. */
struct parse_item_priv {
	enum rte_flow_item_type type;
	uint32_t size;
};

/*
 * Internal buffer for pattern construction.
 * Field names chosen so that the adapted parse_vc/parse_vc_spec
 * can access pattern, pattern_n, data in a straightforward way.
 */
struct pp_buffer {
	uint32_t command;
	struct rte_flow_item *pattern;
	struct rte_flow_action *actions; /* Always NULL (pattern only). */
	uint32_t pattern_n;
	uint8_t *data;
};

/* ---- Macros (same as cmdline_flow.c) ---- */

#define NEXT(...) (const enum index *const []){ __VA_ARGS__, NULL, }
#define NEXT_ENTRY(...) (const enum index []){ __VA_ARGS__, ZERO, }
#define ARGS(...) (const struct arg *const []){ __VA_ARGS__, NULL, }

#define ARGS_ENTRY(s, f) \
	(&(const struct arg){ \
		.offset = offsetof(s, f), \
		.size = sizeof(((s *)0)->f), \
	})

#define ARGS_ENTRY_BF(s, f, b) \
	(&(const struct arg){ \
		.size = sizeof(s), \
		.mask = (const void *)&(const s){ .f = (1 << (b)) - 1 }, \
	})

#define ARGS_ENTRY_BOUNDED(s, f, i, a) \
	(&(const struct arg){ \
		.bounded = 1, \
		.min = (i), \
		.max = (a), \
		.offset = offsetof(s, f), \
		.size = sizeof(((s *)0)->f), \
	})

#define ARGS_ENTRY_MASK(s, f, m) \
	(&(const struct arg){ \
		.offset = offsetof(s, f), \
		.size = sizeof(((s *)0)->f), \
		.mask = (const void *)(m), \
	})

#define ARGS_ENTRY_MASK_HTON(s, f, m) \
	(&(const struct arg){ \
		.hton = 1, \
		.offset = offsetof(s, f), \
		.size = sizeof(((s *)0)->f), \
		.mask = (const void *)(m), \
	})

#define ARGS_ENTRY_PTR(s, f) \
	(&(const struct arg){ \
		.size = sizeof(*((s *)0)->f), \
	})

#define ARGS_ENTRY_ARB(o, s) \
	(&(const struct arg){ \
		.offset = (o), \
		.size = (s), \
	})

#define ARGS_ENTRY_ARB_BOUNDED(o, s, i, a) \
	(&(const struct arg){ \
		.bounded = 1, \
		.min = (i), \
		.max = (a), \
		.offset = (o), \
		.size = (s), \
	})

#define ARGS_ENTRY_HTON(s, f) \
	(&(const struct arg){ \
		.hton = 1, \
		.offset = offsetof(s, f), \
		.size = sizeof(((s *)0)->f), \
	})

#define ARG_ENTRY_HTON(s) \
	(&(const struct arg){ \
		.hton = 1, \
		.offset = 0, \
		.size = sizeof(s), \
	})

#define PRIV_ITEM(t, s) \
	(&(const struct parse_item_priv){ \
		.type = RTE_FLOW_ITEM_TYPE_ ## t, \
		.size = s, \
	})

/* ---- Forward declarations of parse callbacks ---- */

static int parse_vc(struct context *, const struct token *,
		    const char *, unsigned int, void *, unsigned int);
static int parse_vc_spec(struct context *, const struct token *,
			 const char *, unsigned int, void *, unsigned int);
static int parse_vc_item_ecpri_type(struct context *, const struct token *,
				    const char *, unsigned int,
				    void *, unsigned int);
static int parse_vc_item_l2tpv2_type(struct context *, const struct token *,
				     const char *, unsigned int,
				     void *, unsigned int);
static int parse_vc_compare_op(struct context *, const struct token *,
			       const char *, unsigned int,
			       void *, unsigned int);
static int parse_vc_compare_field_id(struct context *, const struct token *,
				     const char *, unsigned int,
				     void *, unsigned int);
static int parse_vc_compare_field_level(struct context *, const struct token *,
					const char *, unsigned int,
					void *, unsigned int);
static int parse_default(struct context *, const struct token *,
			 const char *, unsigned int, void *, unsigned int);
static int parse_int(struct context *, const struct token *,
		     const char *, unsigned int, void *, unsigned int);
static int parse_prefix(struct context *, const struct token *,
			const char *, unsigned int, void *, unsigned int);
static int parse_boolean(struct context *, const struct token *,
			 const char *, unsigned int, void *, unsigned int);
static int parse_string(struct context *, const struct token *,
			const char *, unsigned int, void *, unsigned int);
static int parse_hex(struct context *, const struct token *,
		     const char *, unsigned int, void *, unsigned int);
static int parse_mac_addr(struct context *, const struct token *,
			  const char *, unsigned int, void *, unsigned int);
static int parse_ipv4_addr(struct context *, const struct token *,
			   const char *, unsigned int, void *, unsigned int);
static int parse_ipv6_addr(struct context *, const struct token *,
			   const char *, unsigned int, void *, unsigned int);
static int comp_none(struct context *, const struct token *,
		     unsigned int, char *, unsigned int);
static int comp_boolean(struct context *, const struct token *,
			unsigned int, char *, unsigned int);
static int comp_set_compare_op(struct context *, const struct token *,
			       unsigned int, char *, unsigned int);
static int comp_quota_state_name(struct context *, const struct token *,
				 unsigned int, char *, unsigned int);
static int parse_quota_state_name(struct context *, const struct token *,
				  const char *, unsigned int,
				  void *, unsigned int);
static int comp_set_compare_field_id(struct context *, const struct token *,
				     unsigned int, char *, unsigned int);
/* Stub: flex handle not supported in library context. */
static int parse_flex_handle(struct context *, const struct token *,
			     const char *, unsigned int,
			     void *, unsigned int);
/* Stub: meter policy not supported in library context. */
static int parse_mp(struct context *, const struct token *,
		    const char *, unsigned int,
		    void *, unsigned int);

/* ---- String constants ---- */

static const char *const compare_ops[] = {
	"eq", "ne", "lt", "le", "gt", "ge", NULL
};

static const char *const flow_field_ids[] = {
	"start", "mac_dst", "mac_src",
	"vlan_type", "vlan_id", "mac_type",
	"ipv4_dscp", "ipv4_ttl", "ipv4_src", "ipv4_dst",
	"ipv6_dscp", "ipv6_hoplimit", "ipv6_src", "ipv6_dst",
	"tcp_port_src", "tcp_port_dst",
	"tcp_seq_num", "tcp_ack_num", "tcp_flags",
	"udp_port_src", "udp_port_dst",
	"vxlan_vni", "geneve_vni", "gtp_teid",
	"tag", "mark", "meta", "pointer", "value",
	"ipv4_ecn", "ipv6_ecn", "gtp_psc_qfi", "meter_color",
	"ipv6_proto", "flex_item", "hash_result",
	"geneve_opt_type", "geneve_opt_class", "geneve_opt_data", "mpls",
	"tcp_data_off", "ipv4_ihl", "ipv4_total_len", "ipv6_payload_len",
	"ipv4_proto", "ipv6_flow_label", "ipv6_traffic_class",
	"esp_spi", "esp_seq_num", "esp_proto", "random",
	"vxlan_last_rsvd",
	NULL
};

static const char *const quota_state_names[] = {
	[RTE_FLOW_QUOTA_STATE_PASS] = "pass",
	[RTE_FLOW_QUOTA_STATE_BLOCK] = "block"
};

/* ---- Item arrays (shared grammar) ---- */

#include "rte_flow_pattern_items.inc"

/* ---- Token table ---- */

static const struct token token_list[] = {
	/* Special tokens. */
	[ZERO] = {
		.name = "ZERO",
		.help = "null entry, abused as the entry point",
		.next = NEXT(NEXT_ENTRY(ITEM_PATTERN)),
	},
	[END] = {
		.name = "",
		.type = "RETURN",
		.help = "command may end here",
	},
	[START_SET] = {
		.name = "START_SET",
	},
	[END_SET] = {
		.name = "end_set",
		.type = "RETURN",
		.help = "set command may end here",
	},
	/* Common value tokens. */
	[COMMON_INTEGER] = {
		.name = "{int}",
		.type = "INTEGER",
		.help = "integer value",
		.call = parse_int,
		.comp = comp_none,
	},
	[COMMON_UNSIGNED] = {
		.name = "{unsigned}",
		.type = "UNSIGNED",
		.help = "unsigned integer value",
		.call = parse_int,
		.comp = comp_none,
	},
	[COMMON_PREFIX] = {
		.name = "{prefix}",
		.type = "PREFIX",
		.help = "prefix length for bit-mask",
		.call = parse_prefix,
		.comp = comp_none,
	},
	[COMMON_BOOLEAN] = {
		.name = "{boolean}",
		.type = "BOOLEAN",
		.help = "any boolean value",
		.call = parse_boolean,
		.comp = comp_boolean,
	},
	[COMMON_STRING] = {
		.name = "{string}",
		.type = "STRING",
		.help = "fixed string",
		.call = parse_string,
		.comp = comp_none,
	},
	[COMMON_HEX] = {
		.name = "{hex}",
		.type = "HEX",
		.help = "fixed string",
		.call = parse_hex,
	},
	[COMMON_FILE_PATH] = {
		.name = "{file path}",
		.type = "STRING",
		.help = "file path",
		.call = parse_string,
		.comp = comp_none,
	},
	[COMMON_MAC_ADDR] = {
		.name = "{MAC address}",
		.type = "MAC-48",
		.help = "standard MAC address notation",
		.call = parse_mac_addr,
		.comp = comp_none,
	},
	[COMMON_IPV4_ADDR] = {
		.name = "{IPv4 address}",
		.type = "IPV4 ADDRESS",
		.help = "standard IPv4 address notation",
		.call = parse_ipv4_addr,
		.comp = comp_none,
	},
	[COMMON_IPV6_ADDR] = {
		.name = "{IPv6 address}",
		.type = "IPV6 ADDRESS",
		.help = "standard IPv6 address notation",
		.call = parse_ipv6_addr,
		.comp = comp_none,
	},
	[COMMON_FLEX_HANDLE] = {
		.name = "{flex handle}",
		.type = "FLEX HANDLE",
		.help = "flex item (unsupported in library)",
		.call = parse_flex_handle,
		.comp = comp_none,
	},
	[COMMON_METER_COLOR_NAME] = {
		.name = "{meter color}",
		.type = "METER_COLOR",
		.help = "meter color name",
		.call = parse_int,
		.comp = comp_none,
	},
	[COMMON_POLICY_ID] = {
		.name = "{policy_id}",
		.type = "POLICY_ID",
		.help = "policy id",
		.call = parse_int,
		.comp = comp_none,
	},
	[COMMON_PORT_ID] = {
		.name = "{port_id}",
		.type = "PORT ID",
		.help = "port identifier",
		.call = parse_int,
		.comp = comp_none,
	},
	[ACTIONS] = {
		.name = "actions",
		.help = "end of pattern, start of actions (unused in library)",
	},
	[ACTION_POL_G] = { .name = "" },
	[ACTION_POL_Y] = { .name = "" },
	[ACTION_POL_R] = { .name = "" },
	/* Pattern item tokens from shared grammar. */
#include "rte_flow_pattern_tokens.inc"
};

/* ---- Helper functions (from cmdline_flow.c) ---- */

static const struct arg *
pop_args(struct context *ctx)
{
	return ctx->args_num ? ctx->args[--ctx->args_num] : NULL;
}

static int
push_args(struct context *ctx, const struct arg *arg)
{
	if (ctx->args_num == CTX_STACK_SIZE)
		return -1;
	ctx->args[ctx->args_num++] = arg;
	return 0;
}

static size_t
arg_entry_bf_fill(void *dst, uintmax_t val, const struct arg *arg)
{
	uint32_t i = arg->size;
	uint32_t end = 0;
	int sub = 1;
	int add = 0;
	size_t len = 0;

	if (!arg->mask)
		return 0;
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	if (!arg->hton) {
		i = 0;
		end = arg->size;
		sub = 0;
		add = 1;
	}
#endif
	while (i != end) {
		unsigned int shift = 0;
		uint8_t *buf = (uint8_t *)dst + arg->offset + (i -= sub);

		for (shift = 0; arg->mask[i] >> shift; ++shift) {
			if (!(arg->mask[i] & (1 << shift)))
				continue;
			++len;
			if (!dst)
				continue;
			*buf &= ~(1 << shift);
			*buf |= (val & 1) << shift;
			val >>= 1;
		}
		i += add;
	}
	return len;
}

static int
strcmp_partial(const char *full, const char *partial, size_t partial_len)
{
	int r = strncmp(full, partial, partial_len);

	if (r)
		return r;
	if (strlen(full) <= partial_len)
		return 0;
	return full[partial_len];
}

/* ---- Parse callbacks ---- */

static int
parse_default(struct context *ctx, const struct token *token,
	      const char *str, unsigned int len,
	      void *buf, unsigned int size)
{
	(void)ctx;
	(void)buf;
	(void)size;
	if (strcmp_partial(token->name, str, len))
		return -1;
	return len;
}

/**
 * Adapted parse_vc for pattern-only parsing.
 * Uses struct pp_buffer instead of testpmd's struct buffer.
 */
static int
parse_vc(struct context *ctx, const struct token *token,
	 const char *str, unsigned int len,
	 void *buf, unsigned int size)
{
	struct pp_buffer *out = buf;
	uint8_t *data;
	uint32_t data_size;

	/* Token name must match. */
	if (parse_default(ctx, token, str, len, NULL, 0) < 0)
		return -1;
	if (!out)
		return len;
	if (!out->command) {
		if (sizeof(*out) > size)
			return -1;
		out->command = ITEM_PATTERN;
		ctx->objdata = 0;
		ctx->object = out;
		ctx->objmask = NULL;
		out->data = (uint8_t *)out + size;
		/* Set up pattern pointer immediately since "pattern" is
		 * the first token in library context (no preceding
		 * "validate"/"create" command).
		 */
		out->pattern =
			(void *)RTE_ALIGN_CEIL((uintptr_t)(out + 1),
					       sizeof(double));
		ctx->object = out->pattern;
		return len;
	}
	ctx->objdata = 0;
	ctx->objmask = NULL;
	switch (ctx->curr) {
	case ITEM_PATTERN:
		out->pattern =
			(void *)RTE_ALIGN_CEIL((uintptr_t)(out + 1),
					       sizeof(double));
		ctx->object = out->pattern;
		return len;
	case ITEM_END:
		break;
	default:
		if (!token->priv)
			return -1;
		break;
	}
	/* Pattern item allocation. */
	if (token->priv) {
		const struct parse_item_priv *priv = token->priv;
		struct rte_flow_item *item =
			out->pattern + out->pattern_n;

		data_size = priv->size * 3; /* spec, last, mask */
		data = (void *)RTE_ALIGN_FLOOR((uintptr_t)
					       (out->data - data_size),
					       sizeof(double));
		if ((uint8_t *)item + sizeof(*item) > data)
			return -1;
		*item = (struct rte_flow_item){
			.type = priv->type,
		};
		++out->pattern_n;
		ctx->object = item;
		ctx->objmask = NULL;
		memset(data, 0, data_size);
		out->data = data;
		ctx->objdata = data_size;
	}
	return len;
}

/** Parse pattern item parameter type (is/spec/mask/last/prefix). */
static int
parse_vc_spec(struct context *ctx, const struct token *token,
	      const char *str, unsigned int len,
	      void *buf, unsigned int size)
{
	struct pp_buffer *out = buf;
	struct rte_flow_item *item;
	uint32_t data_size;
	int index;
	int objmask = 0;

	(void)size;
	if (parse_default(ctx, token, str, len, NULL, 0) < 0)
		return -1;
	switch (ctx->curr) {
	case ITEM_PARAM_IS:
		index = 0;
		objmask = 1;
		break;
	case ITEM_PARAM_SPEC:
		index = 0;
		break;
	case ITEM_PARAM_LAST:
		index = 1;
		break;
	case ITEM_PARAM_PREFIX:
		if (ctx->next_num < 2)
			return -1;
		ctx->next[ctx->next_num - 2] = NEXT_ENTRY(COMMON_PREFIX);
		/* Fall through. */
	case ITEM_PARAM_MASK:
		index = 2;
		break;
	default:
		return -1;
	}
	if (!out)
		return len;
	if (!out->pattern_n)
		return -1;
	item = &out->pattern[out->pattern_n - 1];
	data_size = ctx->objdata / 3;
	ctx->object = out->data + (data_size * index);
	if (objmask) {
		ctx->objmask = out->data + (data_size * 2);
		item->mask = ctx->objmask;
	} else
		ctx->objmask = NULL;
	*((const void **[]){ &item->spec, &item->last, &item->mask })[index] =
		ctx->object;
	return len;
}

/** Adapted eCPRI type parser for library buffer. */
static int
parse_vc_item_ecpri_type(struct context *ctx, const struct token *token,
			 const char *str, unsigned int len,
			 void *buf, unsigned int size)
{
	struct rte_flow_item_ecpri *ecpri;
	struct rte_flow_item_ecpri *ecpri_mask;
	struct rte_flow_item *item;
	uint32_t data_size;
	uint8_t msg_type;
	struct pp_buffer *out = buf;
	const struct arg *arg;

	(void)size;
	if (parse_default(ctx, token, str, len, NULL, 0) < 0)
		return -1;
	switch (ctx->curr) {
	case ITEM_ECPRI_COMMON_TYPE_IQ_DATA:
		msg_type = RTE_ECPRI_MSG_TYPE_IQ_DATA;
		break;
	case ITEM_ECPRI_COMMON_TYPE_RTC_CTRL:
		msg_type = RTE_ECPRI_MSG_TYPE_RTC_CTRL;
		break;
	case ITEM_ECPRI_COMMON_TYPE_DLY_MSR:
		msg_type = RTE_ECPRI_MSG_TYPE_DLY_MSR;
		break;
	default:
		return -1;
	}
	if (!ctx->object)
		return len;
	arg = pop_args(ctx);
	if (!arg)
		return -1;
	ecpri = (struct rte_flow_item_ecpri *)out->data;
	ecpri->hdr.common.type = msg_type;
	data_size = ctx->objdata / 3;
	ecpri_mask = (struct rte_flow_item_ecpri *)(out->data +
						    (data_size * 2));
	ecpri_mask->hdr.common.type = 0xFF;
	if (arg->hton) {
		ecpri->hdr.common.u32 =
			rte_cpu_to_be_32(ecpri->hdr.common.u32);
		ecpri_mask->hdr.common.u32 =
			rte_cpu_to_be_32(ecpri_mask->hdr.common.u32);
	}
	item = &out->pattern[out->pattern_n - 1];
	item->spec = ecpri;
	item->mask = ecpri_mask;
	return len;
}

/** Adapted L2TPv2 type parser for library buffer. */
static int
parse_vc_item_l2tpv2_type(struct context *ctx, const struct token *token,
			  const char *str, unsigned int len,
			  void *buf, unsigned int size)
{
	struct rte_flow_item_l2tpv2 *l2tpv2;
	struct rte_flow_item_l2tpv2 *l2tpv2_mask;
	struct rte_flow_item *item;
	uint32_t data_size;
	uint16_t msg_type = 0;
	struct pp_buffer *out = buf;
	const struct arg *arg;

	(void)size;
	if (parse_default(ctx, token, str, len, NULL, 0) < 0)
		return -1;
	switch (ctx->curr) {
	case ITEM_L2TPV2_TYPE_DATA:
		msg_type |= RTE_L2TPV2_MSG_TYPE_DATA;
		break;
	case ITEM_L2TPV2_TYPE_DATA_L:
		msg_type |= RTE_L2TPV2_MSG_TYPE_DATA_L;
		break;
	case ITEM_L2TPV2_TYPE_DATA_S:
		msg_type |= RTE_L2TPV2_MSG_TYPE_DATA_S;
		break;
	case ITEM_L2TPV2_TYPE_DATA_O:
		msg_type |= RTE_L2TPV2_MSG_TYPE_DATA_O;
		break;
	case ITEM_L2TPV2_TYPE_DATA_L_S:
		msg_type |= RTE_L2TPV2_MSG_TYPE_DATA_L_S;
		break;
	case ITEM_L2TPV2_TYPE_CTRL:
		msg_type |= RTE_L2TPV2_MSG_TYPE_CONTROL;
		break;
	default:
		return -1;
	}
	if (!ctx->object)
		return len;
	arg = pop_args(ctx);
	if (!arg)
		return -1;
	l2tpv2 = (struct rte_flow_item_l2tpv2 *)out->data;
	l2tpv2->hdr.common.flags_version |= msg_type;
	data_size = ctx->objdata / 3;
	l2tpv2_mask = (struct rte_flow_item_l2tpv2 *)(out->data +
						      (data_size * 2));
	l2tpv2_mask->hdr.common.flags_version = 0xFFFF;
	if (arg->hton) {
		l2tpv2->hdr.common.flags_version =
			rte_cpu_to_be_16(l2tpv2->hdr.common.flags_version);
		l2tpv2_mask->hdr.common.flags_version =
			rte_cpu_to_be_16(l2tpv2_mask->hdr.common.flags_version);
	}
	item = &out->pattern[out->pattern_n - 1];
	item->spec = l2tpv2;
	item->mask = l2tpv2_mask;
	return len;
}

/** Simplified compare field level (no flex_items in library). */
static int
parse_vc_compare_field_level(struct context *ctx, const struct token *token,
			     const char *str, unsigned int len, void *buf,
			     unsigned int size)
{
	struct rte_flow_item_compare *compare_item;
	uint32_t val;
	char *end;

	(void)token;
	(void)buf;
	(void)size;
	if (ctx->curr != ITEM_COMPARE_FIELD_A_LEVEL_VALUE &&
	    ctx->curr != ITEM_COMPARE_FIELD_B_LEVEL_VALUE)
		return -1;
	if (!ctx->object)
		return len;
	compare_item = ctx->object;
	errno = 0;
	val = strtoumax(str, &end, 0);
	if (errno || (size_t)(end - str) != len)
		return -1;
	if (ctx->curr == ITEM_COMPARE_FIELD_A_LEVEL_VALUE)
		compare_item->a.level = val;
	else
		compare_item->b.level = val;
	return len;
}

/* ---- Value parsers (identical to cmdline_flow.c) ---- */

static int
parse_int(struct context *ctx, const struct token *token,
	  const char *str, unsigned int len,
	  void *buf, unsigned int size)
{
	const struct arg *arg = pop_args(ctx);
	uintmax_t u;
	char *end;

	(void)token;
	if (!arg)
		return -1;
	errno = 0;
	u = arg->sign ?
		(uintmax_t)strtoimax(str, &end, 0) :
		strtoumax(str, &end, 0);
	if (errno || (size_t)(end - str) != len)
		goto error;
	if (arg->bounded &&
	    ((arg->sign && ((intmax_t)u < (intmax_t)arg->min ||
			    (intmax_t)u > (intmax_t)arg->max)) ||
	     (!arg->sign && (u < arg->min || u > arg->max))))
		goto error;
	if (!ctx->object)
		return len;
	if (arg->mask) {
		if (!arg_entry_bf_fill(ctx->object, u, arg) ||
		    !arg_entry_bf_fill(ctx->objmask, -1, arg))
			goto error;
		return len;
	}
	buf = (uint8_t *)ctx->object + arg->offset;
	size = arg->size;
	if (u > RTE_LEN2MASK(size * CHAR_BIT, uint64_t))
		return -1;
objmask:
	switch (size) {
	case sizeof(uint8_t):
		*(uint8_t *)buf = u;
		break;
	case sizeof(uint16_t):
		*(uint16_t *)buf = arg->hton ? rte_cpu_to_be_16(u) : u;
		break;
	case sizeof(uint8_t [3]):
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
		if (!arg->hton) {
			((uint8_t *)buf)[0] = u;
			((uint8_t *)buf)[1] = u >> 8;
			((uint8_t *)buf)[2] = u >> 16;
			break;
		}
#endif
		((uint8_t *)buf)[0] = u >> 16;
		((uint8_t *)buf)[1] = u >> 8;
		((uint8_t *)buf)[2] = u;
		break;
	case sizeof(uint32_t):
		*(uint32_t *)buf = arg->hton ? rte_cpu_to_be_32(u) : u;
		break;
	case sizeof(uint64_t):
		*(uint64_t *)buf = arg->hton ? rte_cpu_to_be_64(u) : u;
		break;
	default:
		goto error;
	}
	if (ctx->objmask && buf != (uint8_t *)ctx->objmask + arg->offset) {
		u = -1;
		buf = (uint8_t *)ctx->objmask + arg->offset;
		goto objmask;
	}
	return len;
error:
	push_args(ctx, arg);
	return -1;
}

static int
parse_prefix(struct context *ctx, const struct token *token,
	     const char *str, unsigned int len,
	     void *buf, unsigned int size)
{
	const struct arg *arg = pop_args(ctx);
	static const uint8_t conv[] = { 0x00, 0x80, 0xc0, 0xe0, 0xf0,
					0xf8, 0xfc, 0xfe, 0xff };
	char *end;
	uintmax_t u;
	unsigned int bytes;
	unsigned int extra;

	(void)token;
	if (!arg)
		return -1;
	errno = 0;
	u = strtoumax(str, &end, 0);
	if (errno || (size_t)(end - str) != len)
		goto error;
	if (arg->mask) {
		uintmax_t v = 0;

		extra = arg_entry_bf_fill(NULL, 0, arg);
		if (u > extra)
			goto error;
		if (!ctx->object)
			return len;
		extra -= u;
		while (u--) {
			v <<= 1;
			v |= 1;
		}
		v <<= extra;
		if (!arg_entry_bf_fill(ctx->object, v, arg) ||
		    !arg_entry_bf_fill(ctx->objmask, -1, arg))
			goto error;
		return len;
	}
	bytes = u / 8;
	extra = u % 8;
	size = arg->size;
	if (bytes > size || bytes + !!extra > size)
		goto error;
	if (!ctx->object)
		return len;
	buf = (uint8_t *)ctx->object + arg->offset;
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	if (!arg->hton) {
		memset((uint8_t *)buf + size - bytes, 0xff, bytes);
		memset(buf, 0x00, size - bytes);
		if (extra)
			((uint8_t *)buf)[size - bytes - 1] = conv[extra];
	} else
#endif
	{
		memset(buf, 0xff, bytes);
		memset((uint8_t *)buf + bytes, 0x00, size - bytes);
		if (extra)
			((uint8_t *)buf)[bytes] = conv[extra];
	}
	if (ctx->objmask)
		memset((uint8_t *)ctx->objmask + arg->offset, 0xff, size);
	return len;
error:
	push_args(ctx, arg);
	return -1;
}

static const char *const boolean_name[] = {
	"0", "1",
	"false", "true",
	"no", "yes",
	"N", "Y",
	"off", "on",
	NULL,
};

static int
parse_boolean(struct context *ctx, const struct token *token,
	      const char *str, unsigned int len,
	      void *buf, unsigned int size)
{
	const struct arg *arg = pop_args(ctx);
	unsigned int i;
	int ret;

	if (!arg)
		return -1;
	for (i = 0; boolean_name[i]; ++i)
		if (!strcmp_partial(boolean_name[i], str, len))
			break;
	if (boolean_name[i])
		str = i & 1 ? "1" : "0";
	push_args(ctx, arg);
	ret = parse_int(ctx, token, str, strlen(str), buf, size);
	return ret > 0 ? (int)len : ret;
}

static int
parse_string(struct context *ctx, const struct token *token,
	     const char *str, unsigned int len,
	     void *buf, unsigned int size)
{
	const struct arg *arg_data = pop_args(ctx);
	const struct arg *arg_len = pop_args(ctx);
	const struct arg *arg_addr = pop_args(ctx);
	char tmp[16];
	int ret;

	if (!arg_data)
		return -1;
	if (!arg_len) {
		push_args(ctx, arg_data);
		return -1;
	}
	if (!arg_addr) {
		push_args(ctx, arg_len);
		push_args(ctx, arg_data);
		return -1;
	}
	size = arg_data->size;
	if (arg_data->mask || size < len)
		goto error;
	if (!ctx->object)
		return len;
	ret = snprintf(tmp, sizeof(tmp), "%u", len);
	if (ret < 0)
		goto error;
	push_args(ctx, arg_len);
	ret = parse_int(ctx, token, tmp, ret, NULL, 0);
	if (ret < 0) {
		pop_args(ctx);
		goto error;
	}
	buf = (uint8_t *)ctx->object + arg_data->offset;
	memcpy(buf, str, len);
	memset((uint8_t *)buf + len, 0x00, size - len);
	if (ctx->objmask)
		memset((uint8_t *)ctx->objmask + arg_data->offset, 0xff, len);
	if (arg_addr->size) {
		memcpy((uint8_t *)ctx->object + arg_addr->offset,
		       (void *[]){
			(uint8_t *)ctx->object + arg_data->offset
		       },
		       arg_addr->size);
		if (ctx->objmask)
			memcpy((uint8_t *)ctx->objmask + arg_addr->offset,
			       (void *[]){
				(uint8_t *)ctx->objmask + arg_data->offset
			       },
			       arg_addr->size);
	}
	return len;
error:
	push_args(ctx, arg_addr);
	push_args(ctx, arg_len);
	push_args(ctx, arg_data);
	return -1;
}

static int
parse_hex_string(const char *src, uint8_t *dst, uint32_t *size)
{
	const uint8_t *head = dst;
	uint32_t left;

	if (*size == 0)
		return -1;
	left = *size;
	while (left) {
		char tmp[3], *end = tmp;
		uint32_t read_lim = left & 1 ? 1 : 2;

		snprintf(tmp, read_lim + 1, "%s", src);
		*dst = strtoul(tmp, &end, 16);
		if (*end) {
			*dst = 0;
			*size = (uint32_t)(dst - head);
			return -1;
		}
		left -= read_lim;
		src += read_lim;
		dst++;
	}
	*dst = 0;
	*size = (uint32_t)(dst - head);
	return 0;
}

static int
parse_hex(struct context *ctx, const struct token *token,
	  const char *str, unsigned int len,
	  void *buf, unsigned int size)
{
	const struct arg *arg_data = pop_args(ctx);
	const struct arg *arg_len = pop_args(ctx);
	const struct arg *arg_addr = pop_args(ctx);
	char tmp[16];
	int ret;
	unsigned int hexlen = len;
	uint8_t hex_tmp[256];

	if (!arg_data)
		return -1;
	if (!arg_len) {
		push_args(ctx, arg_data);
		return -1;
	}
	if (!arg_addr) {
		push_args(ctx, arg_len);
		push_args(ctx, arg_data);
		return -1;
	}
	size = arg_data->size;
	if (arg_data->mask)
		goto error;
	if (!ctx->object)
		return len;
	if (str[0] == '0' && ((str[1] == 'x') || (str[1] == 'X'))) {
		str += 2;
		hexlen -= 2;
	}
	if (hexlen > RTE_DIM(hex_tmp))
		goto error;
	ret = parse_hex_string(str, hex_tmp, &hexlen);
	if (ret < 0)
		goto error;
	if (hexlen > size)
		goto error;
	ret = snprintf(tmp, sizeof(tmp), "%u", hexlen);
	if (ret < 0)
		goto error;
	if (arg_len->size) {
		push_args(ctx, arg_len);
		ret = parse_int(ctx, token, tmp, ret, NULL, 0);
		if (ret < 0) {
			pop_args(ctx);
			goto error;
		}
	}
	buf = (uint8_t *)ctx->object + arg_data->offset;
	memcpy(buf, hex_tmp, hexlen);
	memset((uint8_t *)buf + hexlen, 0x00, size - hexlen);
	if (ctx->objmask)
		memset((uint8_t *)ctx->objmask + arg_data->offset,
		       0xff, hexlen);
	if (arg_addr->size) {
		memcpy((uint8_t *)ctx->object + arg_addr->offset,
		       (void *[]){
			(uint8_t *)ctx->object + arg_data->offset
		       },
		       arg_addr->size);
		if (ctx->objmask)
			memcpy((uint8_t *)ctx->objmask + arg_addr->offset,
			       (void *[]){
				(uint8_t *)ctx->objmask + arg_data->offset
			       },
			       arg_addr->size);
	}
	return len;
error:
	push_args(ctx, arg_addr);
	push_args(ctx, arg_len);
	push_args(ctx, arg_data);
	return -1;
}

/** Parse MAC address (library version, no cmdline dependency). */
static int
parse_mac_addr(struct context *ctx, const struct token *token,
	       const char *str, unsigned int len,
	       void *buf, unsigned int size)
{
	const struct arg *arg = pop_args(ctx);
	struct rte_ether_addr tmp;
	char str2[32];
	unsigned int vals[6];
	int ret;

	(void)token;
	if (!arg)
		return -1;
	size = arg->size;
	if (arg->mask || size != sizeof(tmp))
		goto error;
	if (!arg->hton)
		goto error;
	if (len >= sizeof(str2))
		goto error;
	memcpy(str2, str, len);
	str2[len] = '\0';
	ret = sscanf(str2, "%x:%x:%x:%x:%x:%x",
		     &vals[0], &vals[1], &vals[2],
		     &vals[3], &vals[4], &vals[5]);
	if (ret != 6)
		goto error;
	for (ret = 0; ret < 6; ret++) {
		if (vals[ret] > 0xff)
			goto error;
		tmp.addr_bytes[ret] = (uint8_t)vals[ret];
	}
	if (!ctx->object)
		return len;
	buf = (uint8_t *)ctx->object + arg->offset;
	memcpy(buf, &tmp, size);
	if (ctx->objmask)
		memset((uint8_t *)ctx->objmask + arg->offset, 0xff, size);
	return len;
error:
	push_args(ctx, arg);
	return -1;
}

static int
parse_ipv4_addr(struct context *ctx, const struct token *token,
		const char *str, unsigned int len,
		void *buf, unsigned int size)
{
	const struct arg *arg = pop_args(ctx);
	char str2[INET_ADDRSTRLEN];
	struct in_addr tmp;
	int ret;

	if (len >= INET_ADDRSTRLEN)
		return -1;
	if (!arg)
		return -1;
	size = arg->size;
	if (arg->mask || size != sizeof(tmp))
		goto error;
	if (!arg->hton)
		goto error;
	memcpy(str2, str, len);
	str2[len] = '\0';
	ret = inet_pton(AF_INET, str2, &tmp);
	if (ret != 1) {
		push_args(ctx, arg);
		return parse_int(ctx, token, str, len, buf, size);
	}
	if (!ctx->object)
		return len;
	buf = (uint8_t *)ctx->object + arg->offset;
	memcpy(buf, &tmp, size);
	if (ctx->objmask)
		memset((uint8_t *)ctx->objmask + arg->offset, 0xff, size);
	return len;
error:
	push_args(ctx, arg);
	return -1;
}

static int
parse_ipv6_addr(struct context *ctx, const struct token *token,
		const char *str, unsigned int len,
		void *buf, unsigned int size)
{
	const struct arg *arg = pop_args(ctx);
	char str2[INET6_ADDRSTRLEN];
	struct rte_ipv6_addr tmp;
	int ret;

	(void)token;
	if (len >= INET6_ADDRSTRLEN)
		return -1;
	if (!arg)
		return -1;
	size = arg->size;
	if (arg->mask || size != sizeof(tmp))
		goto error;
	if (!arg->hton)
		goto error;
	memcpy(str2, str, len);
	str2[len] = '\0';
	ret = inet_pton(AF_INET6, str2, &tmp);
	if (ret != 1)
		goto error;
	if (!ctx->object)
		return len;
	buf = (uint8_t *)ctx->object + arg->offset;
	memcpy(buf, &tmp, size);
	if (ctx->objmask)
		memset((uint8_t *)ctx->objmask + arg->offset, 0xff, size);
	return len;
error:
	push_args(ctx, arg);
	return -1;
}

static int
parse_vc_compare_op(struct context *ctx, const struct token *token,
		    const char *str, unsigned int len, void *buf,
		    unsigned int size)
{
	struct rte_flow_item_compare *compare_item;
	unsigned int i;

	(void)token;
	(void)buf;
	(void)size;
	if (ctx->curr != ITEM_COMPARE_OP_VALUE)
		return -1;
	for (i = 0; compare_ops[i]; ++i)
		if (!strcmp_partial(compare_ops[i], str, len))
			break;
	if (!compare_ops[i])
		return -1;
	if (!ctx->object)
		return len;
	compare_item = ctx->object;
	compare_item->operation = (enum rte_flow_item_compare_op)i;
	return len;
}

static int
parse_vc_compare_field_id(struct context *ctx, const struct token *token,
			  const char *str, unsigned int len, void *buf,
			  unsigned int size)
{
	struct rte_flow_item_compare *compare_item;
	unsigned int i;

	(void)token;
	(void)buf;
	(void)size;
	if (ctx->curr != ITEM_COMPARE_FIELD_A_TYPE_VALUE &&
	    ctx->curr != ITEM_COMPARE_FIELD_B_TYPE_VALUE)
		return -1;
	for (i = 0; flow_field_ids[i]; ++i)
		if (!strcmp_partial(flow_field_ids[i], str, len))
			break;
	if (!flow_field_ids[i])
		return -1;
	if (!ctx->object)
		return len;
	compare_item = ctx->object;
	if (ctx->curr == ITEM_COMPARE_FIELD_A_TYPE_VALUE)
		compare_item->a.field = (enum rte_flow_field_id)i;
	else
		compare_item->b.field = (enum rte_flow_field_id)i;
	return len;
}

/* ---- Completion callbacks ---- */

static int
comp_none(struct context *ctx, const struct token *token,
	  unsigned int ent, char *buf, unsigned int size)
{
	(void)ctx;
	(void)token;
	(void)ent;
	(void)buf;
	(void)size;
	return 0;
}

static int
comp_boolean(struct context *ctx, const struct token *token,
	     unsigned int ent, char *buf, unsigned int size)
{
	unsigned int i;

	(void)ctx;
	(void)token;
	for (i = 0; boolean_name[i]; ++i)
		if (buf && i == ent)
			return strlcpy(buf, boolean_name[i], size);
	if (buf)
		return -1;
	return i;
}

static int
comp_set_compare_op(struct context *ctx, const struct token *token,
		    unsigned int ent, char *buf, unsigned int size)
{
	RTE_SET_USED(ctx);
	RTE_SET_USED(token);
	if (!buf)
		return RTE_DIM(compare_ops);
	if (ent < RTE_DIM(compare_ops) - 1)
		return strlcpy(buf, compare_ops[ent], size);
	return -1;
}

static int
comp_names_to_index(struct context *ctx, const struct token *token,
		    unsigned int ent, char *buf, unsigned int size,
		    const char *const names[], size_t names_size)
{
	RTE_SET_USED(ctx);
	RTE_SET_USED(token);
	if (!buf)
		return names_size;
	if (ent < names_size && names[ent] != NULL)
		return rte_strscpy(buf, names[ent], size);
	return -1;
}

static int
comp_quota_state_name(struct context *ctx, const struct token *token,
		      unsigned int ent, char *buf, unsigned int size)
{
	return comp_names_to_index(ctx, token, ent, buf, size,
				   quota_state_names,
				   RTE_DIM(quota_state_names));
}

/** Parse quota state name (stub for quota items). */
static int
parse_quota_state_name(struct context *ctx, const struct token *token,
		       const char *str, unsigned int len,
		       void *buf, unsigned int size)
{
	unsigned int i;

	(void)token;
	(void)buf;
	(void)size;
	for (i = 0; i < RTE_DIM(quota_state_names); ++i) {
		if (quota_state_names[i] &&
		    !strcmp_partial(quota_state_names[i], str, len))
			break;
	}
	if (i >= RTE_DIM(quota_state_names))
		return -1;
	if (!ctx->object)
		return len;
	*(uint32_t *)((uint8_t *)ctx->object +
		      offsetof(struct rte_flow_item_quota, state)) = i;
	return len;
}

/** Complete compare field id. */
static int
comp_set_compare_field_id(struct context *ctx, const struct token *token,
			  unsigned int ent, char *buf, unsigned int size)
{
	RTE_SET_USED(ctx);
	RTE_SET_USED(token);
	if (!buf) {
		unsigned int n = 0;
		while (flow_field_ids[n])
			n++;
		return n;
	}
	if (flow_field_ids[ent])
		return strlcpy(buf, flow_field_ids[ent], size);
	return -1;
}

/** Stub: flex handle not supported in library. */
static int
parse_flex_handle(struct context *ctx, const struct token *token,
		  const char *str, unsigned int len,
		  void *buf, unsigned int size)
{
	(void)ctx;
	(void)token;
	(void)str;
	(void)buf;
	(void)size;
	(void)len;
	return -1;
}

/** Stub: meter policy not supported in library. */
static int
parse_mp(struct context *ctx, const struct token *token,
	 const char *str, unsigned int len,
	 void *buf, unsigned int size)
{
	(void)ctx;
	(void)token;
	(void)str;
	(void)buf;
	(void)size;
	(void)len;
	return -1;
}

/* Add token entries for COMMON_FLEX_HANDLE and COMMON_METER_COLOR_NAME. */

/* ---- Parse engine (based on cmd_flow_parse) ---- */

static void
pp_context_init(struct context *ctx)
{
	ctx->curr = ZERO;
	ctx->prev = ZERO;
	ctx->next_num = 0;
	ctx->args_num = 0;
	ctx->eol = 0;
	ctx->last = 0;
	ctx->port = 0;
	ctx->objdata = 0;
	ctx->object = NULL;
	ctx->objmask = NULL;
}

static struct context pp_parse_ctx;

static int
pp_cmd_parse(const char *src, void *result, unsigned int size)
{
	struct context *ctx = &pp_parse_ctx;
	const struct token *token;
	const enum index *list;
	int len;
	int i;

	token = &token_list[ctx->curr];
	ctx->eol = 0;
	ctx->last = 1;
	for (len = 0; src[len]; ++len)
		if (src[len] == '#' || isspace(src[len]))
			break;
	if (!len)
		return -1;
	for (i = len; src[i]; ++i)
		if (src[i] == '#' || src[i] == '\r' || src[i] == '\n')
			break;
		else if (!isspace(src[i])) {
			ctx->last = 0;
			break;
		}
	for (; src[i]; ++i)
		if (src[i] == '\r' || src[i] == '\n') {
			ctx->eol = 1;
			break;
		}
	if (!ctx->next_num) {
		if (!token->next)
			return 0;
		ctx->next[ctx->next_num++] = token->next[0];
	}
	ctx->prev = ctx->curr;
	list = ctx->next[ctx->next_num - 1];
	for (i = 0; list[i]; ++i) {
		const struct token *next = &token_list[list[i]];
		int tmp;

		ctx->curr = list[i];
		if (next->call)
			tmp = next->call(ctx, next, src, len, result, size);
		else
			tmp = parse_default(ctx, next, src, len, result,
					    size);
		if (tmp == -1 || tmp != len)
			continue;
		token = next;
		break;
	}
	if (!list[i])
		return -1;
	--ctx->next_num;
	if (token->next)
		for (i = 0; token->next[i]; ++i) {
			if (ctx->next_num == RTE_DIM(ctx->next))
				return -1;
			ctx->next[ctx->next_num++] = token->next[i];
		}
	if (token->args)
		for (i = 0; token->args[i]; ++i) {
			if (ctx->args_num == RTE_DIM(ctx->args))
				return -1;
			ctx->args[ctx->args_num++] = token->args[i];
		}
	return len;
}

static int
pp_flow_parse(const char *src, void *result, unsigned int size)
{
	int ret;

	pp_context_init(&pp_parse_ctx);
	do {
		ret = pp_cmd_parse(src, result, size);
		if (ret > 0) {
			src += ret;
			while (isspace(*src))
				src++;
		}
	} while (ret > 0 && *src);
	return (ret >= 0 && !*src) ? 0 : -1;
}

/* ---- Deep copy into self-contained allocation ---- */

static struct rte_flow_item *
pp_deep_copy(const struct rte_flow_item *items, uint32_t n_items,
	     const uint8_t *data_start, uint32_t data_size)
{
	uint32_t items_size, total_size;
	struct rte_flow_item *dst;
	uint8_t *dst_data;
	uint32_t i;

	items_size = RTE_ALIGN_CEIL(n_items * sizeof(*items), sizeof(double));
	total_size = items_size + data_size;

	dst = rte_malloc("flow_pattern", total_size, sizeof(double));
	if (!dst)
		return NULL;
	memcpy(dst, items, n_items * sizeof(*items));
	if (data_size > 0) {
		dst_data = (uint8_t *)dst + items_size;
		memcpy(dst_data, data_start, data_size);
		/* Fix up pointers: they pointed into the parse buffer,
		 * now they must point into the new allocation.
		 */
		for (i = 0; i < n_items; i++) {
			if (dst[i].type == RTE_FLOW_ITEM_TYPE_END)
				break;
#define FIXUP(field) \
	if (dst[i].field && \
	    (const uint8_t *)dst[i].field >= data_start && \
	    (const uint8_t *)dst[i].field < data_start + data_size) \
		dst[i].field = dst_data + \
			((const uint8_t *)dst[i].field - data_start)
			FIXUP(spec);
			FIXUP(mask);
			FIXUP(last);
#undef FIXUP
		}
	}
	return dst;
}

/* ---- Public API ---- */

struct rte_flow_pattern_parser {
	uint32_t magic;
#define PP_MAGIC 0x50415453
};

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_pattern_parser_create, 26.07)
__rte_experimental
struct rte_flow_pattern_parser *
rte_flow_pattern_parser_create(void)
{
	struct rte_flow_pattern_parser *p;

	p = rte_malloc("flow_pp", sizeof(*p), RTE_CACHE_LINE_SIZE);
	if (!p) {
		rte_errno = ENOMEM;
		return NULL;
	}
	p->magic = PP_MAGIC;
	return p;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_pattern_parser_destroy, 26.07)
__rte_experimental
void
rte_flow_pattern_parser_destroy(struct rte_flow_pattern_parser *parser)
{
	if (!parser)
		return;
	parser->magic = 0;
	rte_free(parser);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_pattern_parse, 26.07)
__rte_experimental
int
rte_flow_pattern_parse(struct rte_flow_pattern_parser *parser,
		       const char *pattern_str,
		       struct rte_flow_item **pattern,
		       struct rte_flow_error *error)
{
	uint8_t buf[PP_BUFFER_SIZE] __rte_cache_aligned;
	struct pp_buffer *out = (struct pp_buffer *)buf;
	struct rte_flow_item *result;
	char *input;
	size_t ilen;
	int ret;

	if (!parser || parser->magic != PP_MAGIC ||
	    !pattern_str || !pattern) {
		if (error)
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "invalid arguments");
		return -EINVAL;
	}

	/* Build "pattern <user_string>" input for the token engine. */
	ilen = strlen(pattern_str);
	input = malloc(ilen + 16);
	if (!input) {
		if (error)
			rte_flow_error_set(error, ENOMEM,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "allocation failure");
		return -ENOMEM;
	}
	snprintf(input, ilen + 16, "pattern %s", pattern_str);

	memset(buf, 0, sizeof(*out));
	memset(buf + sizeof(*out), 0x22, sizeof(buf) - sizeof(*out));

	ret = pp_flow_parse(input, buf, sizeof(buf));
	free(input);
	if (ret != 0) {
		if (error)
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				NULL, "pattern parse failed");
		return -EINVAL;
	}

	if (!out->pattern || !out->pattern_n) {
		if (error)
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				NULL, "empty pattern");
		return -EINVAL;
	}
	/* Verify the pattern ends with RTE_FLOW_ITEM_TYPE_END. */
	if (out->pattern[out->pattern_n - 1].type !=
	    RTE_FLOW_ITEM_TYPE_END) {
		if (error)
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				NULL, "missing 'end' keyword");
		return -EINVAL;
	}

	/* Deep-copy: items + spec/mask/last data into one allocation. */
	{
		uint8_t *data_lo = out->data;
		uint8_t *data_hi = buf + sizeof(buf);
		uint32_t data_size = (uint32_t)(data_hi - data_lo);

		result = pp_deep_copy(out->pattern, out->pattern_n,
				      data_lo, data_size);
	}
	if (!result) {
		if (error)
			rte_flow_error_set(error, ENOMEM,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				NULL, "allocation failed");
		return -ENOMEM;
	}
	*pattern = result;
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_pattern_free, 26.07)
__rte_experimental
void
rte_flow_pattern_free(struct rte_flow_item *pattern)
{
	rte_free(pattern);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_pattern_complete, 26.07)
__rte_experimental
int
rte_flow_pattern_complete(struct rte_flow_pattern_parser *parser,
			  const char *partial_str,
			  const char **completions,
			  unsigned int max_completions)
{
	static struct context comp_ctx;
	const struct token *token;
	const enum index *list;
	char *input;
	size_t ilen;
	unsigned int count = 0;
	int ret, i;

	if (!parser || parser->magic != PP_MAGIC ||
	    !partial_str || !completions || !max_completions)
		return -EINVAL;

	/* Parse what we have so far to establish context. */
	ilen = strlen(partial_str);
	input = malloc(ilen + 16);
	if (!input)
		return -ENOMEM;
	snprintf(input, ilen + 16, "pattern %s", partial_str);

	{
		struct context saved = pp_parse_ctx;

		pp_context_init(&pp_parse_ctx);
		const char *src = input;

		while (*src) {
			ret = pp_cmd_parse(src, NULL, 0);
			if (ret <= 0)
				break;
			src += ret;
			while (isspace(*src))
				src++;
		}
		comp_ctx = pp_parse_ctx;
		pp_parse_ctx = saved;
	}
	free(input);

	/* Enumerate candidate tokens. */
	token = &token_list[comp_ctx.curr];
	if (comp_ctx.next_num)
		list = comp_ctx.next[comp_ctx.next_num - 1];
	else if (token->next)
		list = token->next[0];
	else {
		return 0;
	}
	for (i = 0; list[i] && count < max_completions; ++i) {
		const struct token *t = &token_list[list[i]];

		if (t->name && t->name[0] && t->name[0] != '{')
			completions[count++] = t->name;
	}
	return count;
}
