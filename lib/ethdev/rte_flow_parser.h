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
 * standard rte_flow C structures. For the full command parser, cmdline
 * integration, and encap/tunnel configuration accessors, include
 * rte_flow_parser_cmdline.h instead.
 */

#ifndef _RTE_FLOW_PARSER_H_
#define _RTE_FLOW_PARSER_H_

#include <stddef.h>
#include <stdint.h>

#include <rte_compat.h>
#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parse flow attributes from a CLI snippet.
 *
 * Parses attribute strings as used inside a flow command, such as
 * "ingress", "egress", "ingress group 1 priority 5", or "transfer".
 *
 * @warning Not thread-safe. Uses global static storage shared across all
 * threads; concurrent calls from different threads will corrupt state.
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
 * @warning Not thread-safe. Uses global static storage shared across all
 * threads; concurrent calls from different threads will corrupt state.
 *
 * @param src
 *   NUL-terminated pattern string.
 * @param[out] pattern
 *   Output pointer to the parsed pattern array. Points to internal storage
 *   valid until the next parse call.
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
 * @warning Not thread-safe. Uses global static storage shared across all
 * threads; concurrent calls from different threads will corrupt state.
 *
 * @param src
 *   NUL-terminated actions string.
 * @param[out] actions
 *   Output pointer to the parsed actions array. Points to internal storage
 *   valid until the next parse call.
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
 * Parse a complete flow rule string into attr, pattern, and actions.
 *
 * Parses a single string containing attributes, pattern, and actions
 * (e.g., "ingress pattern eth / ipv4 / end actions drop / end") and
 * returns all three components atomically in one call.
 *
 * @warning Not thread-safe. Uses global static storage shared across all
 * threads; concurrent calls from different threads will corrupt state.
 *
 * @param src
 *   NUL-terminated flow rule string.
 * @param[out] attr
 *   Output attributes structure filled on success.
 * @param[out] pattern
 *   Output pointer to the parsed pattern array.
 * @param[out] pattern_n
 *   Number of entries in the pattern array.
 * @param[out] actions
 *   Output pointer to the parsed actions array.
 * @param[out] actions_n
 *   Number of entries in the actions array.
 * @return
 *   0 on success or a negative errno-style value on error.
 */
__rte_experimental
int rte_flow_parser_parse_flow_rule(const char *src,
				    struct rte_flow_attr *attr,
				    const struct rte_flow_item **pattern,
				    uint32_t *pattern_n,
				    const struct rte_flow_action **actions,
				    uint32_t *actions_n);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_FLOW_PARSER_H_ */
