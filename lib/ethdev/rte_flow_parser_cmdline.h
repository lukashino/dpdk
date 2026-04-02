/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 * Copyright 2026 DynaNIC Semiconductors, Ltd.
 */

/**
 * @file
 * Flow Parser Library - Full Command Parsing and Cmdline Integration
 *
 * This header exposes the complete flow command parser, including the
 * rte_flow_parser_parse() function for parsing full flow CLI strings,
 * the rte_flow_parser_apply() function for applying parser-internal
 * commands, and cmdline token integration for building testpmd-like
 * interactive command lines.
 *
 * For simple string-to-flow parsing, use the lightweight helpers in
 * rte_flow_parser.h instead.
 *
 * This header includes rte_flow_parser.h automatically.
 */

#ifndef _RTE_FLOW_PARSER_CMDLINE_H_
#define _RTE_FLOW_PARSER_CMDLINE_H_

#include <stdbool.h>

#include <cmdline_parse.h>
#include <rte_ether.h>
#include <rte_flow_parser.h>
#include <rte_ip.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum size in bytes of a raw encap/decap header blob. */
#define ACTION_RAW_ENCAP_MAX_DATA 512
/** Maximum number of raw encap/decap configuration slots. */
#define RAW_ENCAP_CONFS_MAX_NUM 8
/** Maximum size in bytes of an IPv6 extension push header blob. */
#define ACTION_IPV6_EXT_PUSH_MAX_DATA 512
/** Maximum number of IPv6 extension push configuration slots. */
#define IPV6_EXT_PUSH_CONFS_MAX_NUM 8
/** Maximum number of sub-actions in a sample action. */
#define ACTION_SAMPLE_ACTIONS_NUM 10
/** Maximum number of sample action configuration slots. */
#define RAW_SAMPLE_CONFS_MAX_NUM 8
/** Maximum number of RSS queues in a single action. */
#define ACTION_RSS_QUEUE_NUM 128
/** Number of flow items in a VXLAN encap action definition. */
#define ACTION_VXLAN_ENCAP_ITEMS_NUM 6
/** Number of flow items in an NVGRE encap action definition. */
#define ACTION_NVGRE_ENCAP_ITEMS_NUM 5

/**
 * @name Encap/decap configuration structures
 *
 * These structures hold tunnel encapsulation parameters that the parser
 * reads when constructing VXLAN_ENCAP, NVGRE_ENCAP, L2_ENCAP/DECAP,
 * and MPLSoGRE/MPLSoUDP encap/decap actions. Applications configure
 * them via the accessor functions below before parsing flow rules that
 * reference these actions.
 * @{
 */

/** VXLAN encapsulation parameters. */
struct rte_flow_parser_vxlan_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	uint32_t select_tos_ttl:1; /**< Set TOS/TTL fields. */
	uint8_t vni[3];          /**< VXLAN Network Identifier (big-endian). */
	rte_be16_t udp_src;      /**< Outer UDP source port. */
	rte_be16_t udp_dst;      /**< Outer UDP destination port. */
	rte_be32_t ipv4_src;     /**< Outer IPv4 source address. */
	rte_be32_t ipv4_dst;     /**< Outer IPv4 destination address. */
	struct rte_ipv6_addr ipv6_src; /**< Outer IPv6 source address. */
	struct rte_ipv6_addr ipv6_dst; /**< Outer IPv6 destination address. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	uint8_t ip_tos;          /**< IP Type of Service / Traffic Class. */
	uint8_t ip_ttl;          /**< IP Time to Live / Hop Limit. */
	struct rte_ether_addr eth_src; /**< Outer Ethernet source address. */
	struct rte_ether_addr eth_dst; /**< Outer Ethernet destination address. */
};

/** NVGRE encapsulation parameters. */
struct rte_flow_parser_nvgre_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	uint8_t tni[3];          /**< Tenant Network Identifier (big-endian). */
	rte_be32_t ipv4_src;     /**< Outer IPv4 source address. */
	rte_be32_t ipv4_dst;     /**< Outer IPv4 destination address. */
	struct rte_ipv6_addr ipv6_src; /**< Outer IPv6 source address. */
	struct rte_ipv6_addr ipv6_dst; /**< Outer IPv6 destination address. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	struct rte_ether_addr eth_src; /**< Outer Ethernet source address. */
	struct rte_ether_addr eth_dst; /**< Outer Ethernet destination address. */
};

/** L2 encapsulation parameters. */
struct rte_flow_parser_l2_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	struct rte_ether_addr eth_src; /**< Outer Ethernet source address. */
	struct rte_ether_addr eth_dst; /**< Outer Ethernet destination address. */
};

/** L2 decapsulation parameters. */
struct rte_flow_parser_l2_decap_conf {
	uint32_t select_vlan:1;  /**< Expect VLAN header in decap. */
};

/** MPLSoGRE encapsulation parameters. */
struct rte_flow_parser_mplsogre_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	uint8_t label[3];        /**< MPLS label (big-endian). */
	rte_be32_t ipv4_src;     /**< Outer IPv4 source address. */
	rte_be32_t ipv4_dst;     /**< Outer IPv4 destination address. */
	struct rte_ipv6_addr ipv6_src; /**< Outer IPv6 source address. */
	struct rte_ipv6_addr ipv6_dst; /**< Outer IPv6 destination address. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	struct rte_ether_addr eth_src; /**< Outer source MAC. */
	struct rte_ether_addr eth_dst; /**< Outer destination MAC. */
};

/** MPLSoGRE decapsulation parameters. */
struct rte_flow_parser_mplsogre_decap_conf {
	uint32_t select_ipv4:1;  /**< Expect IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Expect VLAN header. */
};

/** MPLSoUDP encapsulation parameters. */
struct rte_flow_parser_mplsoudp_encap_conf {
	uint32_t select_ipv4:1;  /**< Use IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Include VLAN header. */
	uint8_t label[3];        /**< MPLS label (big-endian). */
	rte_be16_t udp_src;      /**< Outer UDP source port. */
	rte_be16_t udp_dst;      /**< Outer UDP destination port. */
	rte_be32_t ipv4_src;     /**< Outer IPv4 source address. */
	rte_be32_t ipv4_dst;     /**< Outer IPv4 destination address. */
	struct rte_ipv6_addr ipv6_src; /**< Outer IPv6 source address. */
	struct rte_ipv6_addr ipv6_dst; /**< Outer IPv6 destination address. */
	rte_be16_t vlan_tci;     /**< VLAN Tag Control Information. */
	struct rte_ether_addr eth_src; /**< Outer source MAC. */
	struct rte_ether_addr eth_dst; /**< Outer destination MAC. */
};

/** MPLSoUDP decapsulation parameters. */
struct rte_flow_parser_mplsoudp_decap_conf {
	uint32_t select_ipv4:1;  /**< Expect IPv4 (1) or IPv6 (0). */
	uint32_t select_vlan:1;  /**< Expect VLAN header. */
};

/** @} */

/**
 * Tunnel steering/match flags used by the parser.
 */
struct rte_flow_parser_tunnel_ops {
	uint32_t id;         /**< Tunnel object identifier. */
	char type[16];       /**< Tunnel type name (e.g., "vxlan"). */
	uint32_t enabled:1;  /**< Tunnel steering enabled. */
	uint32_t actions:1;  /**< Apply tunnel to actions. */
	uint32_t items:1;    /**< Apply tunnel to pattern items. */
};

/**
 * Flow parser command identifiers.
 *
 * These identify the command type in the rte_flow_parser_output structure
 * after a successful parse. Internal grammar tokens used during parsing
 * are not exposed.
 *
 * When adding a new command, update the conversion in parser_token_to_command().
 */
enum rte_flow_parser_command {
	RTE_FLOW_PARSER_CMD_UNKNOWN = 0,

	/* Flow operations */
	RTE_FLOW_PARSER_CMD_INFO,
	RTE_FLOW_PARSER_CMD_CONFIGURE,
	RTE_FLOW_PARSER_CMD_VALIDATE,
	RTE_FLOW_PARSER_CMD_CREATE,
	RTE_FLOW_PARSER_CMD_DESTROY,
	RTE_FLOW_PARSER_CMD_UPDATE,
	RTE_FLOW_PARSER_CMD_FLUSH,
	RTE_FLOW_PARSER_CMD_DUMP_ALL,
	RTE_FLOW_PARSER_CMD_DUMP_ONE,
	RTE_FLOW_PARSER_CMD_QUERY,
	RTE_FLOW_PARSER_CMD_LIST,
	RTE_FLOW_PARSER_CMD_AGED,
	RTE_FLOW_PARSER_CMD_ISOLATE,
	RTE_FLOW_PARSER_CMD_PUSH,
	RTE_FLOW_PARSER_CMD_PULL,
	RTE_FLOW_PARSER_CMD_HASH,

	/* Template operations */
	RTE_FLOW_PARSER_CMD_PATTERN_TEMPLATE_CREATE,
	RTE_FLOW_PARSER_CMD_PATTERN_TEMPLATE_DESTROY,
	RTE_FLOW_PARSER_CMD_ACTIONS_TEMPLATE_CREATE,
	RTE_FLOW_PARSER_CMD_ACTIONS_TEMPLATE_DESTROY,

	/* Table operations */
	RTE_FLOW_PARSER_CMD_TABLE_CREATE,
	RTE_FLOW_PARSER_CMD_TABLE_DESTROY,
	RTE_FLOW_PARSER_CMD_TABLE_RESIZE,
	RTE_FLOW_PARSER_CMD_TABLE_RESIZE_COMPLETE,

	/* Group operations */
	RTE_FLOW_PARSER_CMD_GROUP_SET_MISS_ACTIONS,

	/* Queue operations */
	RTE_FLOW_PARSER_CMD_QUEUE_CREATE,
	RTE_FLOW_PARSER_CMD_QUEUE_DESTROY,
	RTE_FLOW_PARSER_CMD_QUEUE_UPDATE,
	RTE_FLOW_PARSER_CMD_QUEUE_FLOW_UPDATE_RESIZED,
	RTE_FLOW_PARSER_CMD_QUEUE_AGED,

	/* Indirect action operations */
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_CREATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_LIST_CREATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_UPDATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_DESTROY,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_QUERY,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_QUERY_UPDATE,

	/* Queue indirect action operations */
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_CREATE,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_LIST_CREATE,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_UPDATE,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_DESTROY,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_QUERY,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_QUERY_UPDATE,

	/* Tunnel operations */
	RTE_FLOW_PARSER_CMD_TUNNEL_CREATE,
	RTE_FLOW_PARSER_CMD_TUNNEL_DESTROY,
	RTE_FLOW_PARSER_CMD_TUNNEL_LIST,

	/* Flex item operations */
	RTE_FLOW_PARSER_CMD_FLEX_ITEM_CREATE,
	RTE_FLOW_PARSER_CMD_FLEX_ITEM_DESTROY,

	/* Meter policy */
	RTE_FLOW_PARSER_CMD_ACTION_POL_G,

	/* Set commands (used by apply) */
	RTE_FLOW_PARSER_CMD_SET_RAW_ENCAP,
	RTE_FLOW_PARSER_CMD_SET_RAW_DECAP,
	RTE_FLOW_PARSER_CMD_SET_SAMPLE_ACTIONS,
	RTE_FLOW_PARSER_CMD_SET_IPV6_EXT_PUSH,
	RTE_FLOW_PARSER_CMD_SET_IPV6_EXT_REMOVE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_FLOW_CONF_CREATE,
};

/** Parser output buffer layout expected by rte_flow_parser_parse(). */
struct rte_flow_parser_output {
	enum rte_flow_parser_command command; /**< Flow command. */
	uint16_t port; /**< Affected port ID. */
	uint16_t queue; /**< Async queue ID. */
	bool postpone; /**< Postpone async operation. */
	union {
		struct {
			struct rte_flow_port_attr port_attr;
			uint32_t nb_queue;
			struct rte_flow_queue_attr queue_attr;
		} configure; /**< Configuration arguments. */
		struct {
			uint32_t *template_id;
			uint32_t template_id_n;
		} templ_destroy; /**< Template destroy arguments. */
		struct {
			uint32_t id;
			struct rte_flow_template_table_attr attr;
			uint32_t *pat_templ_id;
			uint32_t pat_templ_id_n;
			uint32_t *act_templ_id;
			uint32_t act_templ_id_n;
		} table; /**< Table arguments. */
		struct {
			uint32_t *table_id;
			uint32_t table_id_n;
		} table_destroy; /**< Table destroy arguments. */
		struct {
			uint32_t *action_id;
			uint32_t action_id_n;
		} ia_destroy; /**< Indirect action destroy arguments. */
		struct {
			uint32_t action_id;
			enum rte_flow_query_update_mode qu_mode;
		} ia; /**< Indirect action query arguments. */
		struct {
			uint32_t table_id;
			uint32_t pat_templ_id;
			uint32_t rule_id;
			uint32_t act_templ_id;
			struct rte_flow_attr attr;
			struct rte_flow_parser_tunnel_ops tunnel_ops;
			uintptr_t user_id;
			struct rte_flow_item *pattern;
			struct rte_flow_action *actions;
			struct rte_flow_action *masks;
			uint32_t pattern_n;
			uint32_t actions_n;
			uint8_t *data;
			enum rte_flow_encap_hash_field field;
			uint8_t encap_hash;
			bool is_user_id;
		} vc; /**< Validate/create arguments. */
		struct {
			uint64_t *rule;
			uint64_t rule_n;
			bool is_user_id;
		} destroy; /**< Destroy arguments. */
		struct {
			char file[128];
			bool mode;
			uint64_t rule;
			bool is_user_id;
		} dump; /**< Dump arguments. */
		struct {
			uint64_t rule;
			struct rte_flow_action action;
			bool is_user_id;
		} query; /**< Query arguments. */
		struct {
			uint32_t *group;
			uint32_t group_n;
		} list; /**< List arguments. */
		struct {
			int set;
		} isolate; /**< Isolated mode arguments. */
		struct {
			int destroy;
		} aged; /**< Aged arguments. */
		struct {
			uint32_t policy_id;
		} policy; /**< Policy arguments. */
		struct {
			uint16_t token;
			uintptr_t uintptr;
			char filename[128];
		} flex; /**< Flex arguments. */
	} args; /**< Command arguments. */
};


/**
 * Parse a flow CLI string.
 *
 * Parses a complete flow or set command string and fills the output buffer.
 * Parser-internal commands (set raw_encap, set raw_decap, set sample_actions,
 * set ipv6_ext_push, set ipv6_ext_remove, indirect_action flow_conf create)
 * are automatically applied via rte_flow_parser_apply().
 *
 * @warning Not thread-safe. Uses global static storage shared across all
 * threads; concurrent calls from different threads will corrupt state.
 *
 * @param src
 *   NUL-terminated string containing one or more flow commands.
 * @param result
 *   Output buffer where the parsed result is stored.
 * @param result_size
 *   Size of the output buffer in bytes.
 * @return
 *   0 on success, -EINVAL on syntax error, -ENOBUFS if result_size is too
 *   small, or a negative errno-style value on other errors.
 */
__rte_experimental
int rte_flow_parser_parse(const char *src,
			  struct rte_flow_parser_output *result,
			  size_t result_size);

/**
 * Apply parser-internal commands from a parsed output buffer.
 *
 * Handles SET commands (raw_encap, raw_decap, sample_actions,
 * ipv6_ext_push, ipv6_ext_remove) and indirect_action flow_conf create.
 * This is called automatically by rte_flow_parser_parse(); applications
 * only need to call it explicitly when constructing output buffers manually.
 *
 * @warning Not thread-safe. Modifies global static storage shared across
 * all threads.
 *
 * @param in
 *   Parsed output buffer.
 * @return
 *   0 on success, negative errno on failure.
 */
__rte_experimental
int rte_flow_parser_apply(const struct rte_flow_parser_output *in);

/**
 * Dispatch callback type for parsed flow commands.
 *
 * Called by rte_flow_parser_cmd_flow_cb() after the cmdline library
 * finishes parsing a complete flow command. The application implements
 * this to act on the parsed result (e.g., call port_flow_create()).
 *
 * @param in
 *   Parsed output buffer containing the command and its arguments.
 */
typedef void (*rte_flow_parser_dispatch_t)(const struct rte_flow_parser_output *in);

/**
 * Register cmdline instances and flow dispatch callback.
 *
 * Stores references to the application's cmdline_parse_inst_t
 * structures so that the library can:
 *   - detect the first-token position for context initialization,
 *   - update inst->help_str dynamically for context-sensitive help.
 *
 * @note The library writes to flow->help_str and set_raw->help_str
 * during interactive parsing. The instances must remain valid for
 * the lifetime of the cmdline session.
 *
 * @warning Not thread-safe.
 *
 * @param flow
 *   cmdline instance for flow commands (tokens[0] must be NULL).
 * @param set_raw
 *   cmdline instance for set commands (tokens[0] must be NULL).
 * @param dispatch
 *   Application callback invoked for parsed flow commands.
 *   Not called for SET commands (those are auto-applied internally).
 */
__rte_experimental
void rte_flow_parser_cmdline_register(cmdline_parse_inst_t *flow,
				      cmdline_parse_inst_t *set_raw,
				      rte_flow_parser_dispatch_t dispatch);

/**
 * Cmdline callback for flow commands.
 *
 * Suitable for direct use as the .f member of a cmdline_parse_inst_t
 * with .tokens[0] = NULL (dynamic token mode). Handles both dynamic
 * token population (called by cmdline internally) and command dispatch
 * (calls the dispatch function registered via
 * rte_flow_parser_cmdline_register()).
 *
 * Encapsulates the cmdline dynamic token protocol so that the
 * application does not need to implement the cl == NULL routing.
 *
 * Example usage:
 * @code
 * cmdline_parse_inst_t cmd_flow = {
 *     .f = rte_flow_parser_cmd_flow_cb,
 *     .tokens = { NULL },
 * };
 * @endcode
 *
 * @param arg0
 *   Token header pointer (when populating tokens) or parsed output
 *   buffer (when dispatching a completed command).
 * @param cl
 *   Cmdline handle; NULL when the cmdline library is requesting a
 *   dynamic token, non-NULL when a complete command was parsed.
 * @param arg2
 *   Token slot address (when populating tokens) or inst->data
 *   (when dispatching).
 */
__rte_experimental
void rte_flow_parser_cmd_flow_cb(void *arg0, struct cmdline *cl, void *arg2);

/**
 * Cmdline callback for set commands (raw_encap, raw_decap, etc.).
 *
 * Same usage as rte_flow_parser_cmd_flow_cb(). Parser-internal
 * commands are auto-applied via rte_flow_parser_apply(); no dispatch
 * callback is invoked.
 *
 * @param arg0
 *   Token header pointer or parsed output buffer.
 * @param cl
 *   Cmdline handle; NULL for token population, non-NULL for dispatch.
 * @param arg2
 *   Token slot address or inst->data.
 */
__rte_experimental
void rte_flow_parser_cmd_set_raw_cb(void *arg0, struct cmdline *cl,
				    void *arg2);

/**
 * @name Encap/decap and conntrack configuration accessors
 *
 * These return mutable pointers to parser-internal global state.
 * Applications use them to configure tunnel encapsulation parameters
 * (e.g., VNI, IP addresses, MAC addresses) before parsing flow rules
 * that use the corresponding encap/decap actions.
 *
 * @warning Not thread-safe. The returned pointers refer to global parser
 * state that may be modified by any subsequent parser API call.
 * @{
 */

/**
 * Get VXLAN encapsulation configuration.
 *
 * @return
 *   Pointer to mutable VXLAN encap configuration.
 */
__rte_experimental
struct rte_flow_parser_vxlan_encap_conf *rte_flow_parser_vxlan_encap_conf(void);

/**
 * Get NVGRE encapsulation configuration.
 *
 * @return
 *   Pointer to mutable NVGRE encap configuration.
 */
__rte_experimental
struct rte_flow_parser_nvgre_encap_conf *rte_flow_parser_nvgre_encap_conf(void);

/**
 * Get L2 encapsulation configuration.
 *
 * @return
 *   Pointer to mutable L2 encap configuration.
 */
__rte_experimental
struct rte_flow_parser_l2_encap_conf *rte_flow_parser_l2_encap_conf(void);

/**
 * Get L2 decapsulation configuration.
 *
 * @return
 *   Pointer to mutable L2 decap configuration.
 */
__rte_experimental
struct rte_flow_parser_l2_decap_conf *rte_flow_parser_l2_decap_conf(void);

/**
 * Get MPLSoGRE encapsulation configuration.
 *
 * @return
 *   Pointer to mutable MPLSoGRE encap configuration.
 */
__rte_experimental
struct rte_flow_parser_mplsogre_encap_conf *rte_flow_parser_mplsogre_encap_conf(void);

/**
 * Get MPLSoGRE decapsulation configuration.
 *
 * @return
 *   Pointer to mutable MPLSoGRE decap configuration.
 */
__rte_experimental
struct rte_flow_parser_mplsogre_decap_conf *rte_flow_parser_mplsogre_decap_conf(void);

/**
 * Get MPLSoUDP encapsulation configuration.
 *
 * @return
 *   Pointer to mutable MPLSoUDP encap configuration.
 */
__rte_experimental
struct rte_flow_parser_mplsoudp_encap_conf *rte_flow_parser_mplsoudp_encap_conf(void);

/**
 * Get MPLSoUDP decapsulation configuration.
 *
 * @return
 *   Pointer to mutable MPLSoUDP decap configuration.
 */
__rte_experimental
struct rte_flow_parser_mplsoudp_decap_conf *rte_flow_parser_mplsoudp_decap_conf(void);

/**
 * Get raw encap configuration for the given slot index.
 *
 * Returns a snapshot of the raw encap data previously stored by
 * parsing a "set raw_encap <index> ..." command.
 *
 * @param index
 *   Slot index (0 to RAW_ENCAP_CONFS_MAX_NUM - 1).
 * @return
 *   Pointer to raw encap configuration, or NULL if index is out of range.
 */
__rte_experimental
const struct rte_flow_action_raw_encap *rte_flow_parser_raw_encap_conf_get(uint16_t index);

/**
 * Get raw decap configuration for the given slot index.
 *
 * Returns a snapshot of the raw decap data previously stored by
 * parsing a "set raw_decap <index> ..." command.
 *
 * @param index
 *   Slot index (0 to RAW_ENCAP_CONFS_MAX_NUM - 1).
 * @return
 *   Pointer to raw decap configuration, or NULL if index is out of range.
 */
__rte_experimental
const struct rte_flow_action_raw_decap *rte_flow_parser_raw_decap_conf_get(uint16_t index);

/**
 * Get the conntrack action context.
 *
 * @return
 *   Pointer to mutable conntrack configuration.
 */
__rte_experimental
struct rte_flow_action_conntrack *rte_flow_parser_conntrack_context(void);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_FLOW_PARSER_CMDLINE_H_ */
