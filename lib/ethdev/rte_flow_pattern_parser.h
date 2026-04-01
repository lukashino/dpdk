/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Open vSwitch community
 */

#ifndef RTE_FLOW_PATTERN_PARSER_H_
#define RTE_FLOW_PATTERN_PARSER_H_

/**
 * @file
 *
 * RTE flow pattern string parser.
 *
 * Provides a public API for parsing human-readable rte_flow pattern strings
 * (using testpmd syntax) into struct rte_flow_item arrays. This allows
 * external applications such as Suricata IDS to parse rte_flow pattern
 * strings without depending on testpmd code.
 *
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 */

#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Opaque parser context. Holds token tables, completion state,
 * and internal buffers. Allows multiple independent parser instances.
 */
struct rte_flow_pattern_parser;

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Allocate and initialize a pattern parser context.
 *
 * The context encapsulates the token/grammar tables needed
 * for parsing. It can be reused across multiple parse calls.
 * Each context instance is independent; multiple threads may
 * use separate contexts concurrently without synchronization.
 *
 * @return
 *   Non-NULL pointer on success, NULL on failure (rte_errno is set).
 */
__rte_experimental
struct rte_flow_pattern_parser *
rte_flow_pattern_parser_create(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Destroy a pattern parser context and free associated resources.
 *
 * @param parser
 *   Parser context previously created by rte_flow_pattern_parser_create().
 *   If NULL, no operation is performed.
 */
__rte_experimental
void
rte_flow_pattern_parser_destroy(struct rte_flow_pattern_parser *parser);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Parse a pattern string into an array of rte_flow_item.
 *
 * The input string uses testpmd flow pattern syntax:
 *   "eth / ipv4 dst is 192.168.1.1 / tcp dst is 80 / end"
 *
 * Items are separated by " / ". The array is terminated by an item
 * of type RTE_FLOW_ITEM_TYPE_END. All spec/mask/last data is deep-copied
 * into a single contiguous allocation -- the returned pointer can be freed
 * with rte_flow_pattern_free().
 *
 * @param parser
 *   Parser context from rte_flow_pattern_parser_create().
 * @param pattern_str
 *   Null-terminated pattern string in testpmd syntax.
 * @param[out] pattern
 *   On success, set to point to a heap-allocated array of rte_flow_item.
 *   Terminated by RTE_FLOW_ITEM_TYPE_END. Caller must free via
 *   rte_flow_pattern_free().
 * @param[out] error
 *   Optional (may be NULL). On failure, filled with a human-readable
 *   error message and the byte offset in pattern_str where parsing failed.
 *
 * @return
 *   0 on success, negative errno on failure.
 *   -EINVAL: malformed pattern string.
 *   -ENOMEM: allocation failure.
 *   -ENOTSUP: unknown item type encountered.
 */
__rte_experimental
int
rte_flow_pattern_parse(struct rte_flow_pattern_parser *parser,
		       const char *pattern_str,
		       struct rte_flow_item **pattern,
		       struct rte_flow_error *error);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Free a pattern array previously returned by rte_flow_pattern_parse().
 *
 * Handles the contiguous allocation (items + spec/mask/last data).
 * After this call the pointer is invalid.
 *
 * @param pattern
 *   Pattern array to free. If NULL, no operation is performed.
 */
__rte_experimental
void
rte_flow_pattern_free(struct rte_flow_item *pattern);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Provide completion suggestions for a partial pattern string.
 *
 * This supports tab-completion in interactive tools. Given a partial
 * input, returns possible next tokens (item types or field names).
 *
 * @param parser
 *   Parser context.
 * @param partial_str
 *   The partial pattern string typed so far.
 * @param[out] completions
 *   Caller-allocated array of string pointers. Filled with pointers
 *   to static token name strings (do NOT free them).
 * @param max_completions
 *   Size of the completions array.
 *
 * @return
 *   Number of completions written (0 if none), or negative errno on error.
 */
__rte_experimental
int
rte_flow_pattern_complete(struct rte_flow_pattern_parser *parser,
			  const char *partial_str,
			  const char **completions,
			  unsigned int max_completions);

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_PATTERN_PARSER_H_ */
