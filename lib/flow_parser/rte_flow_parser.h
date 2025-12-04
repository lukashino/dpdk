/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef RTE_FLOW_PARSER_H
#define RTE_FLOW_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rte_compat.h>
#include <cmdline_parse.h>
#include <rte_flow.h>
#include <rte_ip.h>
#include <rte_ether.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rte_flow_parser;
struct rte_flow_parser_rss_type_info {
	const char *str;
	uint64_t rss_type;
};

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
	uint8_t eth_src[RTE_ETHER_ADDR_LEN];
	uint8_t eth_dst[RTE_ETHER_ADDR_LEN];
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
	uint8_t eth_src[RTE_ETHER_ADDR_LEN];
	uint8_t eth_dst[RTE_ETHER_ADDR_LEN];
};

struct rte_flow_parser_l2_encap_conf {
	uint32_t select_ipv4:1;
	uint32_t select_vlan:1;
	rte_be16_t vlan_tci;
	uint8_t eth_src[RTE_ETHER_ADDR_LEN];
	uint8_t eth_dst[RTE_ETHER_ADDR_LEN];
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

/* Maximum number of patterns supported by the parser. */
#define RTE_FLOW_PARSER_MAX_PATTERNS   64
/* Maximum number of flex items supported by the parser. */
#define RTE_FLOW_PARSER_MAX_FLEX_ITEMS 8

/**
 * Tunnel steering/match flags used by the parser. This mirrors testpmd's
 * structure but is kept small for applications to fill in.
 */
struct rte_flow_parser_tunnel_ops {
	uint32_t id;
	char type[16];
	uint32_t enabled:1;
	uint32_t actions:1;
	uint32_t items:1;
};

enum rte_flow_parser_command {
	RTE_FLOW_PARSER_CMD_NONE = 0,
	RTE_FLOW_PARSER_CMD_INFO,
	RTE_FLOW_PARSER_CMD_CONFIGURE,
	RTE_FLOW_PARSER_CMD_PATTERN_TEMPLATE_CREATE,
	RTE_FLOW_PARSER_CMD_PATTERN_TEMPLATE_DESTROY,
	RTE_FLOW_PARSER_CMD_ACTIONS_TEMPLATE_CREATE,
	RTE_FLOW_PARSER_CMD_ACTIONS_TEMPLATE_DESTROY,
	RTE_FLOW_PARSER_CMD_TABLE_CREATE,
	RTE_FLOW_PARSER_CMD_TABLE_DESTROY,
	RTE_FLOW_PARSER_CMD_TABLE_RESIZE,
	RTE_FLOW_PARSER_CMD_TABLE_RESIZE_COMPLETE,
	RTE_FLOW_PARSER_CMD_GROUP_SET_MISS_ACTIONS,
	RTE_FLOW_PARSER_CMD_QUEUE_CREATE,
	RTE_FLOW_PARSER_CMD_QUEUE_DESTROY,
	RTE_FLOW_PARSER_CMD_QUEUE_FLOW_UPDATE_RESIZED,
	RTE_FLOW_PARSER_CMD_QUEUE_UPDATE,
	RTE_FLOW_PARSER_CMD_QUEUE_AGED,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_CREATE,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_LIST_CREATE,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_UPDATE,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_DESTROY,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_QUERY,
	RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_QUERY_UPDATE,
	RTE_FLOW_PARSER_CMD_PUSH,
	RTE_FLOW_PARSER_CMD_PULL,
	RTE_FLOW_PARSER_CMD_HASH,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_CREATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_LIST_CREATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_UPDATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_DESTROY,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_QUERY,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_QUERY_UPDATE,
	RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_FLOW_CONF_CREATE,
	RTE_FLOW_PARSER_CMD_VALIDATE,
	RTE_FLOW_PARSER_CMD_CREATE,
	RTE_FLOW_PARSER_CMD_DESTROY,
	RTE_FLOW_PARSER_CMD_UPDATE,
	RTE_FLOW_PARSER_CMD_FLUSH,
	RTE_FLOW_PARSER_CMD_DUMP_ONE,
	RTE_FLOW_PARSER_CMD_DUMP_ALL,
	RTE_FLOW_PARSER_CMD_QUERY,
	RTE_FLOW_PARSER_CMD_LIST,
	RTE_FLOW_PARSER_CMD_ISOLATE,
	RTE_FLOW_PARSER_CMD_AGED,
	RTE_FLOW_PARSER_CMD_TUNNEL_CREATE,
	RTE_FLOW_PARSER_CMD_TUNNEL_DESTROY,
	RTE_FLOW_PARSER_CMD_TUNNEL_LIST,
	RTE_FLOW_PARSER_CMD_METER_POLICY_ADD,
	RTE_FLOW_PARSER_CMD_FLEX_ITEM_CREATE,
	RTE_FLOW_PARSER_CMD_FLEX_ITEM_DESTROY,
	RTE_FLOW_PARSER_CMD_SET_RAW_ENCAP,
	RTE_FLOW_PARSER_CMD_SET_RAW_DECAP,
	RTE_FLOW_PARSER_CMD_SET_SAMPLE_ACTIONS,
	RTE_FLOW_PARSER_CMD_SET_IPV6_EXT_PUSH,
	RTE_FLOW_PARSER_CMD_SET_IPV6_EXT_REMOVE,
};

/**
 * Unified output buffer produced by the parser. Users must provide a buffer
 * of at least sizeof(struct rte_flow_parser_output) to rte_flow_parser_parse().
 */
struct rte_flow_parser_output {
	enum rte_flow_parser_command command;
	uint16_t port;
	uint16_t queue;
	bool postpone;
	union {
		struct {
			struct rte_flow_port_attr port_attr;
			uint32_t nb_queue;
			struct rte_flow_queue_attr queue_attr;
		} configure;
		struct {
			uint32_t *template_id;
			uint32_t template_id_n;
		} templ_destroy;
		struct {
			uint32_t id;
			struct rte_flow_template_table_attr attr;
			uint32_t *pat_templ_id;
			uint32_t pat_templ_id_n;
			uint32_t *act_templ_id;
			uint32_t act_templ_id_n;
		} table;
		struct {
			uint32_t *table_id;
			uint32_t table_id_n;
		} table_destroy;
		struct {
			uint32_t *action_id;
			uint32_t action_id_n;
		} ia_destroy;
		struct {
			uint32_t action_id;
			enum rte_flow_query_update_mode qu_mode;
		} ia;
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
		} flow;
		struct {
			uint64_t *rule;
			uint64_t rule_n;
			bool is_user_id;
		} destroy;
		struct {
			char file[128];
			bool mode;
			uint64_t rule;
			bool is_user_id;
		} dump;
		struct {
			uint64_t rule;
			struct rte_flow_action action;
			bool is_user_id;
		} query;
		struct {
			uint32_t *group;
			uint32_t group_n;
		} list;
		struct {
			int set;
		} isolate;
		struct {
			int destroy;
		} aged;
		struct {
			uint32_t policy_id;
		} policy;
		struct {
			uint16_t token;
			uintptr_t uintptr;
			char filename[128];
		} flex;
	} args;
};

/**
 * Query hooks: the parser consults these to validate IDs and fetch cached
 * objects for completions or rule composition.
 */
struct rte_flow_parser_query_ops {
	int (*port_validate)(uint16_t port_id, bool warn, void *userdata);
	uint16_t (*flow_rule_count)(uint16_t port_id, void *userdata);
	int (*flow_rule_id_get)(uint16_t port_id, unsigned int index,
			      uint64_t *rule_id, void *userdata);
	uint16_t (*pattern_template_count)(uint16_t port_id, void *userdata);
	int (*pattern_template_id_get)(uint16_t port_id, unsigned int index,
				     uint32_t *template_id, void *userdata);
	uint16_t (*actions_template_count)(uint16_t port_id, void *userdata);
	int (*actions_template_id_get)(uint16_t port_id, unsigned int index,
				        uint32_t *template_id, void *userdata);
	uint16_t (*table_count)(uint16_t port_id, void *userdata);
	int (*table_id_get)(uint16_t port_id, unsigned int index,
			    uint32_t *table_id, void *userdata);
	uint16_t (*queue_count)(uint16_t port_id, void *userdata);
	uint16_t (*rss_queue_count)(uint16_t port_id, void *userdata);
	struct rte_flow_template_table *(*table_get)(uint16_t port_id,
						    uint32_t table_id,
						    void *userdata);
	struct rte_flow_action_handle *(*action_handle_get)(uint16_t port_id,
						       uint32_t action_id,
						       void *userdata);
	struct rte_flow_meter_profile *(*meter_profile_get)(uint16_t port_id,
						      uint32_t profile_id,
						      void *userdata);
	struct rte_flow_meter_policy *(*meter_policy_get)(uint16_t port_id,
						     uint32_t policy_id,
						     void *userdata);
	struct rte_flow_item_flex_handle *(*flex_handle_get)(uint16_t port_id,
						     uint16_t flex_id,
						     void *userdata);
	const struct rte_flow_action_raw_encap *(*raw_encap_conf_get)
			(uint16_t index, void *userdata);
	const struct rte_flow_action_raw_decap *(*raw_decap_conf_get)
			(uint16_t index, void *userdata);
	const struct rte_flow_action_ipv6_ext_push *(*ipv6_ext_push_conf_get)
			(uint16_t index, void *userdata);
	const struct rte_flow_action_ipv6_ext_remove *(*ipv6_ext_remove_conf_get)
			(uint16_t index, void *userdata);
	const struct rte_flow_action *(*sample_actions_get)
			(uint16_t index, void *userdata);
	const struct rte_flow_parser_rss_type_info *(*rss_type_table_get)
			(void *userdata);
	uint64_t (*rss_hf_get)(void *userdata);
	const struct rte_flow_parser_vxlan_encap_conf *(*vxlan_encap_conf_get)
			(void *userdata);
	const struct rte_flow_parser_nvgre_encap_conf *(*nvgre_encap_conf_get)
			(void *userdata);
	const struct rte_flow_parser_l2_encap_conf *(*l2_encap_conf_get)
			(void *userdata);
	const struct rte_flow_parser_l2_decap_conf *(*l2_decap_conf_get)
			(void *userdata);
	const struct rte_flow_parser_mplsogre_encap_conf *(*mplsogre_encap_conf_get)
			(void *userdata);
	const struct rte_flow_parser_mplsogre_decap_conf *(*mplsogre_decap_conf_get)
			(void *userdata);
	const struct rte_flow_parser_mplsoudp_encap_conf *(*mplsoudp_encap_conf_get)
			(void *userdata);
	const struct rte_flow_parser_mplsoudp_decap_conf *(*mplsoudp_decap_conf_get)
			(void *userdata);
	uint16_t (*verbose_level_get)(void *userdata);
	int (*flex_pattern_get)(uint16_t pattern_id,
			       const struct rte_flow_item_flex **spec,
			       const struct rte_flow_item_flex **mask,
			       void *userdata);
};

/**
 * Command hooks: executed when the parser accepts a command. Applications
 * should implement the callbacks they need; unused callbacks may be NULL.
 */
struct rte_flow_parser_command_ops {
	void (*flow_get_info)(uint16_t port_id, void *userdata);
	void (*flow_configure)(uint16_t port_id,
			const struct rte_flow_port_attr *port_attr,
			uint32_t nb_queue,
			const struct rte_flow_queue_attr *queue_attr,
			void *userdata);
	void (*flow_pattern_template_create)(uint16_t port_id, uint32_t id,
				 const struct rte_flow_pattern_template_attr *attr,
				 const struct rte_flow_item pattern[],
				 void *userdata);
	void (*flow_pattern_template_destroy)(uint16_t port_id,
				 uint32_t nb_id, const uint32_t id[],
				 void *userdata);
	void (*flow_actions_template_create)(uint16_t port_id, uint32_t id,
				 const struct rte_flow_actions_template_attr *attr,
				 const struct rte_flow_action actions[],
				 const struct rte_flow_action masks[],
				 void *userdata);
	void (*flow_actions_template_destroy)(uint16_t port_id,
				 uint32_t nb_id, const uint32_t id[],
				 void *userdata);
	void (*flow_template_table_create)(uint16_t port_id, uint32_t table_id,
			 const struct rte_flow_template_table_attr *attr,
			 uint32_t nb_pattern, const uint32_t pattern_id[],
			 uint32_t nb_action, const uint32_t action_id[],
			 void *userdata);
	void (*flow_template_table_destroy)(uint16_t port_id, uint32_t nb_id,
			 const uint32_t id[], void *userdata);
	void (*flow_template_table_resize_complete)(uint16_t port_id,
			uint32_t table_id, void *userdata);
	void (*queue_group_set_miss_actions)(uint16_t port_id,
			const struct rte_flow_attr *attr,
			const struct rte_flow_action actions[],
			void *userdata);
	void (*flow_template_table_resize)(uint16_t port_id, uint32_t table_id,
			 uint32_t nb_rules, void *userdata);
	void (*queue_flow_create)(uint16_t port_id, uint16_t queue,
			  bool postpone, uint32_t table_id,
			  uint32_t rule_id, uint32_t pattern_template_id,
			  uint32_t action_template_id,
			  const struct rte_flow_item pattern[],
			  const struct rte_flow_action actions[],
			  void *userdata);
	void (*queue_flow_destroy)(uint16_t port_id, uint16_t queue,
			   bool postpone, uint32_t nb_rule,
			   const uint64_t rule[], bool is_user_id,
			   void *userdata);
	void (*queue_flow_update_resized)(uint16_t port_id, uint16_t queue,
			 bool postpone, uint64_t rule_id, void *userdata);
	void (*queue_flow_update)(uint16_t port_id, uint16_t queue,
			 bool postpone, uint32_t rule_id,
			 uint32_t action_template_id,
			 const struct rte_flow_action actions[],
			 void *userdata);
	void (*queue_flow_push)(uint16_t port_id, uint16_t queue, void *userdata);
	void (*queue_flow_pull)(uint16_t port_id, uint16_t queue, void *userdata);
	void (*flow_hash_calc)(uint16_t port_id, uint32_t table_id,
		    uint32_t pattern_template_id,
		    const struct rte_flow_item pattern[], void *userdata);
	void (*flow_hash_calc_encap)(uint16_t port_id,
		       enum rte_flow_encap_hash_field field,
		       const struct rte_flow_item pattern[], void *userdata);
	void (*queue_flow_aged)(uint16_t port_id, uint16_t queue,
		    bool destroy, void *userdata);
	void (*queue_action_handle_create)(uint16_t port_id, uint16_t queue,
		     bool postpone, uint32_t group,
		     bool is_list, const struct rte_flow_indir_action_conf *conf,
		     const struct rte_flow_action actions[], void *userdata);
	void (*queue_action_handle_destroy)(uint16_t port_id, uint16_t queue,
		     bool postpone, uint32_t nb_id, const uint32_t id[],
		     void *userdata);
	void (*queue_action_handle_update)(uint16_t port_id, uint16_t queue,
		     bool postpone, uint32_t group,
		     const struct rte_flow_action actions[], void *userdata);
	void (*queue_action_handle_query)(uint16_t port_id, uint16_t queue,
		     bool postpone, uint32_t action_id, void *userdata);
	void (*queue_action_handle_query_update)(uint16_t port_id,
		     uint16_t queue, bool postpone, uint32_t action_id,
		     enum rte_flow_query_update_mode qu_mode,
		     struct rte_flow_action actions[], void *userdata);
	void (*action_handle_create)(uint16_t port_id, uint32_t group,
		    bool is_list, const struct rte_flow_indir_action_conf *conf,
		    const struct rte_flow_action actions[], void *userdata);
	void (*action_handle_destroy)(uint16_t port_id, uint32_t nb_id,
		    const uint32_t id[], void *userdata);
	void (*action_handle_update)(uint16_t port_id, uint32_t group,
		    const struct rte_flow_action actions[], void *userdata);
	void (*action_handle_query)(uint16_t port_id, uint32_t action_id,
		    void *userdata);
	void (*action_handle_query_update)(uint16_t port_id, uint32_t action_id,
		    enum rte_flow_query_update_mode qu_mode,
		    struct rte_flow_action actions[], void *userdata);
	void (*flow_validate)(uint16_t port_id, const struct rte_flow_attr *attr,
		  const struct rte_flow_item pattern[],
		  const struct rte_flow_action actions[],
		  const struct rte_flow_parser_tunnel_ops *ops, void *userdata);
	void (*flow_create)(uint16_t port_id, const struct rte_flow_attr *attr,
		 const struct rte_flow_item pattern[],
		 const struct rte_flow_action actions[],
		 const struct rte_flow_parser_tunnel_ops *ops, uintptr_t user_id,
		 void *userdata);
	void (*flow_destroy)(uint16_t port_id, uint32_t nb_rule,
		 const uint64_t rule[], bool is_user_id, void *userdata);
	void (*flow_update)(uint16_t port_id, uint32_t rule_id,
		 const struct rte_flow_action actions[], uintptr_t user_id,
		 void *userdata);
	void (*flow_flush)(uint16_t port_id, void *userdata);
	void (*flow_dump)(uint16_t port_id, bool all, uint64_t rule,
		 const char *file, bool is_user_id, void *userdata);
	void (*flow_query)(uint16_t port_id, uint64_t rule,
		 struct rte_flow_action *action, bool is_user_id,
		 void *userdata);
	void (*flow_list)(uint16_t port_id, uint32_t group_n,
		 const uint32_t group[], void *userdata);
	void (*flow_isolate)(uint16_t port_id, int set, void *userdata);
	void (*flow_aged)(uint16_t port_id, int destroy, void *userdata);
	void (*flow_tunnel_create)(uint16_t port_id,
		 const struct rte_flow_parser_tunnel_ops *ops, void *userdata);
	void (*flow_tunnel_destroy)(uint16_t port_id, uint32_t id,
		 void *userdata);
	void (*flow_tunnel_list)(uint16_t port_id, void *userdata);
	void (*meter_policy_add)(uint16_t port_id, uint32_t policy_id,
		 const struct rte_flow_action actions[], void *userdata);
	void (*flex_item_create)(uint16_t port_id, uint16_t flex_id,
		 const char *filename, void *userdata);
	void (*flex_item_destroy)(uint16_t port_id, uint16_t flex_id,
		 void *userdata);
	void (*set_raw_encap)(uint16_t index,
		 const struct rte_flow_item pattern[], uint32_t pattern_n,
		 void *userdata);
	void (*set_raw_decap)(uint16_t index,
		 const struct rte_flow_item pattern[], uint32_t pattern_n,
		 void *userdata);
	void (*set_sample_actions)(uint16_t index,
		 const struct rte_flow_action actions[], uint32_t actions_n,
		 void *userdata);
	void (*set_ipv6_ext_push)(uint16_t index,
		 const struct rte_flow_item pattern[], uint32_t pattern_n,
		 void *userdata);
	void (*set_ipv6_ext_remove)(uint16_t index,
		 const struct rte_flow_item pattern[], uint32_t pattern_n,
		 void *userdata);
};

struct rte_flow_parser_ops {
	const struct rte_flow_parser_query_ops *query;
	const struct rte_flow_parser_command_ops *command;
};

/**
 * Create a flow parser instance.
 *
 * @param ops
 *   Callback table providing query/command hooks. May be NULL to use only
 *   defaults.
 * @param userdata
 *   Opaque pointer returned to all callbacks.
 * @return
 *   New parser instance or NULL on error.
 */
__rte_experimental
struct rte_flow_parser *
rte_flow_parser_create(const struct rte_flow_parser_ops *ops,
			 void *userdata);

/**
 * Destroy a flow parser instance.
 *
 * @param parser
 *   Parser handle returned by rte_flow_parser_create().
 */
__rte_experimental
void rte_flow_parser_destroy(struct rte_flow_parser *parser);

/**
 * Retrieve cmdline instance for "flow" commands.
 */
__rte_experimental
cmdline_parse_inst_t *
rte_flow_parser_cmd_flow(struct rte_flow_parser *parser);
/**
 * Retrieve cmdline instance for "set raw" commands.
 */
__rte_experimental
cmdline_parse_inst_t *
rte_flow_parser_cmd_set_raw(struct rte_flow_parser *parser);
/**
 * Retrieve cmdline instance for "show set raw" command.
 */
__rte_experimental
cmdline_parse_inst_t *
rte_flow_parser_cmd_show_set_raw(struct rte_flow_parser *parser);
/**
 * Retrieve cmdline instance for "show set raw all" command.
 */
__rte_experimental
cmdline_parse_inst_t *
rte_flow_parser_cmd_show_set_raw_all(struct rte_flow_parser *parser);

/**
 * Set default ops for the global parser (testpmd integration helper).
 */
__rte_experimental
int rte_flow_parser_set_default_ops(const struct rte_flow_parser_ops *ops,
				    void *userdata);

/**
 * Parse a flow CLI string.
 *
 * @param parser
 *   Parser instance (may be NULL to use the default one).
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
int rte_flow_parser_parse(struct rte_flow_parser *parser, const char *src,
			 struct rte_flow_parser_output *result,
			 size_t result_size);

/**
 * Parse only flow attributes from a CLI snippet.
 *
 * @param src
 *   Attribute string as used inside a flow command, e.g. "ingress group 1".
 * @param attr
 *   Output attributes structure filled on success.
 * @return
 *   0 on success or a negative errno-style value on error.
 *
 * The returned pointer refers to internal storage valid until the next call
 * on the same thread.
 */
__rte_experimental
int rte_flow_parser_parse_attr_str(const char *src, struct rte_flow_attr *attr);

/**
 * Parse only a flow pattern from a CLI snippet.
 *
 * @param src
 *   Pattern string as used inside a flow command, e.g. "eth / ipv4 / end".
 * @param pattern
 *   Output pointer to the parsed pattern array (internal storage).
 * @param pattern_n
 *   Number of entries in the pattern array.
 * @return
 *   0 on success or a negative errno-style value on error.
 *
 * The returned pointers refer to internal storage valid until the next call
 * on the same thread.
 */
__rte_experimental
int rte_flow_parser_parse_pattern_str(const char *src,
				      const struct rte_flow_item **pattern,
				      uint32_t *pattern_n);

/**
 * Parse only flow actions from a CLI snippet.
 *
 * @param src
 *   Actions string as used inside a flow command, e.g. "queue index 5 / end".
 * @param actions
 *   Output pointer to the parsed actions array (internal storage).
 * @param actions_n
 *   Number of entries in the actions array.
 * @return
 *   0 on success or a negative errno-style value on error.
 *
 * The returned pointers refer to internal storage valid until the next call
 * on the same thread.
 */
__rte_experimental
int rte_flow_parser_parse_actions_str(const char *src,
				      const struct rte_flow_action **actions,
				      uint32_t *actions_n);

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_PARSER_H */
