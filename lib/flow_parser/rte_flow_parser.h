/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025
 */

#ifndef RTE_FLOW_PARSER_H
#define RTE_FLOW_PARSER_H

#include <stdint.h>

#include <rte_common.h>
#include <rte_compat.h>
#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rte_flow_parse_attr {
	uint32_t max_pattern_items;
	uint32_t max_actions;
	uint32_t socket_id;
};

struct rte_flow_parse_result {
	struct rte_flow_attr attr;
	struct rte_flow_item *pattern;
	uint32_t pattern_count;
	struct rte_flow_action *actions;
	uint32_t actions_count;
	uint16_t port_id;
};

struct rte_flow_parser;

#define RTE_FLOW_PARSER_DEFAULT_PATTERN_ITEMS 32U
#define RTE_FLOW_PARSER_DEFAULT_ACTIONS 32U

__rte_experimental
struct rte_flow_parser *
rte_flow_parser_create(const struct rte_flow_parse_attr *attr,
			    struct rte_flow_error *error);

__rte_experimental
int
rte_flow_parser_reset(struct rte_flow_parser *parser,
		       struct rte_flow_error *error);

__rte_experimental
int
rte_flow_parser_rule(struct rte_flow_parser *parser,
		      const char *input,
		      struct rte_flow_parse_result *result,
		      struct rte_flow_error *error);

__rte_experimental
int
rte_flow_parser_pattern(struct rte_flow_parser *parser,
		 const char *pattern_str,
		 struct rte_flow_item **pattern_out,
		 uint32_t *pattern_count,
		 struct rte_flow_error *error);

__rte_experimental
int
rte_flow_parser_actions(struct rte_flow_parser *parser,
		 const char *actions_str,
		 struct rte_flow_action **actions_out,
		 uint32_t *actions_count,
		 struct rte_flow_error *error);

__rte_experimental
void
rte_flow_parser_destroy(struct rte_flow_parser *parser);

__rte_experimental
void
rte_flow_parse_result_free(struct rte_flow_parser *parser,
			      struct rte_flow_parse_result *result);

__rte_experimental
void
rte_flow_parser_pattern_free(struct rte_flow_parser *parser,
		            struct rte_flow_item *pattern);

__rte_experimental
void
rte_flow_parser_actions_free(struct rte_flow_parser *parser,
		            struct rte_flow_action *actions);

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_PARSER_H */
