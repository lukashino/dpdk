/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <eal_export.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_memory.h>

#include <rte_flow_driver.h>

#include "rte_flow_parser.h"

struct rte_flow_parser {
	uint32_t max_pattern_items;
	uint32_t max_actions;
	int socket_id;
};

struct token_list {
	char **data;
	size_t count;
	size_t capacity;
};

static void
parser_defaults(struct rte_flow_parser *parser, const struct rte_flow_parse_attr *attr)
{
	parser->max_pattern_items = attr && attr->max_pattern_items ?
		attr->max_pattern_items : RTE_FLOW_PARSER_DEFAULT_PATTERN_ITEMS;
	parser->max_actions = attr && attr->max_actions ?
		attr->max_actions : RTE_FLOW_PARSER_DEFAULT_ACTIONS;
	parser->socket_id = attr ? (int)attr->socket_id : SOCKET_ID_ANY;
}

static void
token_list_reset(struct token_list *list)
{
	if (!list)
		return;
	for (size_t i = 0; i < list->count; ++i)
		rte_free(list->data[i]);
	rte_free(list->data);
	list->data = NULL;
	list->count = 0;
	list->capacity = 0;
}

static int
token_list_append(struct rte_flow_parser *parser, struct token_list *list,
		 const char *start, size_t len)
{
	char *copy;
	if (!list->capacity) {
		list->capacity = 32;
		list->data = rte_zmalloc_socket("flow_tokens",
				list->capacity * sizeof(*list->data),
				0, parser->socket_id);
		if (!list->data)
			return -ENOMEM;
	}
	if (list->count == list->capacity) {
		size_t new_cap = list->capacity * 2;
		char **new_data = rte_realloc(list->data,
				new_cap * sizeof(*new_data),
				0);
		if (!new_data)
			return -ENOMEM;
		list->data = new_data;
		list->capacity = new_cap;
	}
	copy = rte_zmalloc_socket("flow_token", len + 1, 0, parser->socket_id);
	if (!copy)
		return -ENOMEM;
	memcpy(copy, start, len);
	copy[len] = '\0';
	list->data[list->count++] = copy;
	return 0;
}

static bool
is_token_delim(char c)
{
	return isspace((unsigned char)c) || c == '/';
}

static int
tokenize(struct rte_flow_parser *parser, const char *input,
	 struct token_list *out)
{
	const char *p = input;
	while (*p) {
		if (*p == '\\' && (p[1] == '\n' || p[1] == '\r')) {
			p += 2;
			continue;
		}
		if (isspace((unsigned char)*p)) {
			++p;
			continue;
		}
		if (*p == '/') {
			int ret = token_list_append(parser, out, p, 1);
			if (ret)
				return ret;
			++p;
			continue;
		}
		const char *start = p;
		while (*p && !is_token_delim(*p))
			++p;
		if (start != p) {
			int ret = token_list_append(parser, out, start, (size_t)(p - start));
			if (ret)
				return ret;
		}
	}
	return 0;
}

static int
error_set(struct rte_flow_error *error, int code, enum rte_flow_error_type type,
	  const char *msg)
{
	return rte_flow_error_set(error, code, type, NULL, msg);
}

static int
parse_uint32(const char *token, uint32_t *value)
{
	char *end = NULL;
	errno = 0;
	unsigned long v = strtoul(token, &end, 0);
	if (errno || !end || *end != '\0' || v > UINT32_MAX)
		return -EINVAL;
	*value = (uint32_t)v;
	return 0;
}

static int
parse_ipv4_addr(const char *token, uint32_t *addr)
{
	struct in_addr in4;
	if (inet_pton(AF_INET, token, &in4) != 1)
		return -EINVAL;
	*addr = in4.s_addr;
	return 0;
}

static int
parse_ipv6_addr(const char *token, uint8_t dst[16])
{
	struct in6_addr in6;
	if (inet_pton(AF_INET6, token, &in6) != 1)
		return -EINVAL;
	memcpy(dst, &in6, sizeof(in6));
	return 0;
}

static int
ensure_capacity(uint32_t limit, uint32_t count, struct rte_flow_error *error,
	       const char *what)
{
	if (count >= limit)
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_UNSPECIFIED, what);
	return 0;
}

static int
parse_item_eth(struct rte_flow_parser *parser, struct rte_flow_item *item,
	      struct rte_flow_error *error)
{
	(void)parser;
	(void)error;
	item->type = RTE_FLOW_ITEM_TYPE_ETH;
	item->spec = NULL;
	item->mask = NULL;
	item->last = NULL;
	return 0;
}

static int
parse_item_ipv4(struct rte_flow_parser *parser, struct token_list *tokens,
	        size_t *idx, struct rte_flow_item *item,
	        struct rte_flow_error *error)
{
	struct rte_flow_item_ipv4 *spec;
	struct rte_flow_item_ipv4 *mask;

	(void)parser;
	spec = rte_zmalloc_socket("flow_ipv4_spec",
			 sizeof(*spec), 0, parser->socket_id);
	if (!spec)
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_ITEM_SPEC,
				   "failed to allocate IPv4 spec");
	mask = rte_zmalloc_socket("flow_ipv4_mask",
			 sizeof(*mask), 0, parser->socket_id);
	if (!mask) {
		rte_free(spec);
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_ITEM_MASK,
				   "failed to allocate IPv4 mask");
	}
	while (*idx < tokens->count) {
		char *token = tokens->data[*idx];
		if (!strcasecmp(token, "/") || !strcasecmp(token, "end") ||
		    !strcasecmp(token, "actions"))
			break;
		if (!strcasecmp(token, "src") || !strcasecmp(token, "dst")) {
			bool is_src = !strcasecmp(token, "src");
			++(*idx);
			if (*idx >= tokens->count)
				goto ipv4_syntax_error;
			char *qualifier = tokens->data[*idx];
			if (strcasecmp(qualifier, "is") &&
			    strcasecmp(qualifier, "spec"))
				goto ipv4_syntax_error;
			++(*idx);
			if (*idx >= tokens->count)
				goto ipv4_syntax_error;
			char *value = tokens->data[*idx];
			uint32_t addr;
			if (parse_ipv4_addr(value, &addr))
				goto ipv4_syntax_error;
			if (is_src)
				spec->hdr.src_addr = addr;
			else
				spec->hdr.dst_addr = addr;
			if (is_src)
				mask->hdr.src_addr = UINT32_MAX;
			else
				mask->hdr.dst_addr = UINT32_MAX;
			++(*idx);
			continue;
		}
		goto ipv4_syntax_error;
	}
	item->type = RTE_FLOW_ITEM_TYPE_IPV4;
	item->spec = spec;
	item->mask = mask;
	item->last = NULL;
	return 0;

ipv4_syntax_error:
	rte_free(spec);
	rte_free(mask);
	return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_SPEC,
			 "invalid IPv4 pattern token");
}

static int
parse_item_ipv6(struct rte_flow_parser *parser, struct token_list *tokens,
	        size_t *idx, struct rte_flow_item *item,
	        struct rte_flow_error *error)
{
	struct rte_flow_item_ipv6 *spec;
	struct rte_flow_item_ipv6 *mask;

	spec = rte_zmalloc_socket("flow_ipv6_spec",
			 sizeof(*spec), 0, parser->socket_id);
	if (!spec)
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_ITEM_SPEC,
				   "failed to allocate IPv6 spec");
	mask = rte_zmalloc_socket("flow_ipv6_mask",
			 sizeof(*mask), 0, parser->socket_id);
	if (!mask) {
		rte_free(spec);
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_ITEM_MASK,
				   "failed to allocate IPv6 mask");
	}
	while (*idx < tokens->count) {
		char *token = tokens->data[*idx];
		if (!strcasecmp(token, "/") || !strcasecmp(token, "end") ||
		    !strcasecmp(token, "actions"))
			break;
		if (!strcasecmp(token, "src") || !strcasecmp(token, "dst")) {
			bool is_src = !strcasecmp(token, "src");
			++(*idx);
			if (*idx >= tokens->count)
				goto ipv6_syntax_error;
			char *qualifier = tokens->data[*idx];
			if (!strcasecmp(qualifier, "spec") || !strcasecmp(qualifier, "is")) {
				++(*idx);
				if (*idx >= tokens->count)
					goto ipv6_syntax_error;
				char *value = tokens->data[*idx];
				if (parse_ipv6_addr(value, is_src ?
						spec->hdr.src_addr.a :
						spec->hdr.dst_addr.a))
					goto ipv6_syntax_error;
				if (is_src)
					memset(mask->hdr.src_addr.a, 0xFF, sizeof(mask->hdr.src_addr.a));
				else
					memset(mask->hdr.dst_addr.a, 0xFF, sizeof(mask->hdr.dst_addr.a));
				++(*idx);
				continue;
			}
			if (!strcasecmp(qualifier, "mask")) {
				++(*idx);
				if (*idx >= tokens->count)
					goto ipv6_syntax_error;
				char *value = tokens->data[*idx];
				if (parse_ipv6_addr(value, is_src ?
					mask->hdr.src_addr.a :
					mask->hdr.dst_addr.a))
					goto ipv6_syntax_error;
				++(*idx);
				continue;
			}
			goto ipv6_syntax_error;
		}
		goto ipv6_syntax_error;
	}
	item->type = RTE_FLOW_ITEM_TYPE_IPV6;
	item->spec = spec;
	item->mask = mask;
	item->last = NULL;
	return 0;

ipv6_syntax_error:
	rte_free(spec);
	rte_free(mask);
	return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_SPEC,
			 "invalid IPv6 pattern token");
}

static void
pattern_cleanup(struct rte_flow_item *items, uint32_t count)
{
	if (!items)
		return;
	for (uint32_t i = 0; i < count; ++i) {
		rte_free((void *)(uintptr_t)items[i].spec);
		rte_free((void *)(uintptr_t)items[i].mask);
		rte_free((void *)(uintptr_t)items[i].last);
	}
}

static void
actions_cleanup(struct rte_flow_action *actions, uint32_t count)
{
	if (!actions)
		return;
	for (uint32_t i = 0; i < count; ++i)
		rte_free((void *)(uintptr_t)actions[i].conf);
}

static int
parse_pattern_section(struct rte_flow_parser *parser, struct token_list *tokens,
		       size_t *idx, struct rte_flow_parse_result *result,
		       struct rte_flow_error *error)
{
	uint32_t count = 0;
	struct rte_flow_item *items;

	items = rte_zmalloc_socket("flow_pattern",
			 (parser->max_pattern_items + 1) * sizeof(*items),
			 0, parser->socket_id);
	if (!items)
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "failed to allocate pattern array");

	while (*idx < tokens->count) {
		char *token = tokens->data[*idx];
		if (!strcasecmp(token, "actions"))
			break;
		if (!strcasecmp(token, "/")) {
			++(*idx);
			continue;
		}
		if (!strcasecmp(token, "end")) {
			++(*idx);
			goto pattern_done;
		}
		int cap = ensure_capacity(parser->max_pattern_items, count, error,
			"too many pattern items");
		if (cap) {
			pattern_cleanup(items, count);
			rte_free(items);
			return cap;
		}
		++(*idx);
		if (!strcasecmp(token, "eth")) {
			if (parse_item_eth(parser, &items[count], error)) {
				pattern_cleanup(items, count);
				rte_free(items);
				return -1;
			}
		} else if (!strcasecmp(token, "ipv4")) {
			if (parse_item_ipv4(parser, tokens, idx, &items[count], error)) {
				pattern_cleanup(items, count);
				rte_free(items);
				return -1;
			}
		} else if (!strcasecmp(token, "ipv6")) {
			if (parse_item_ipv6(parser, tokens, idx, &items[count], error)) {
				pattern_cleanup(items, count);
				rte_free(items);
				return -1;
			}
		} else {
			pattern_cleanup(items, count);
			rte_free(items);
			return error_set(error, ENOTSUP,
					 RTE_FLOW_ERROR_TYPE_ITEM,
					 "unsupported pattern item");
		}
		++count;
	}
	pattern_cleanup(items, count);
	rte_free(items);
	return error_set(error, EINVAL,
			 RTE_FLOW_ERROR_TYPE_ITEM,
			 "pattern section missing end");

pattern_done:
	items[count].type = RTE_FLOW_ITEM_TYPE_END;
	result->pattern = items;
	result->pattern_count = count;
	return 0;
}

static int
parse_action_drop(struct rte_flow_action *action)
{
	action->type = RTE_FLOW_ACTION_TYPE_DROP;
	action->conf = NULL;
	return 0;
}

static int
parse_action_mark(struct rte_flow_parser *parser, struct token_list *tokens,
	          size_t *idx, struct rte_flow_action *action,
	          struct rte_flow_error *error)
{
	struct rte_flow_action_mark *mark;
	if (*idx >= tokens->count)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "expected id qualifier");
	if (strcasecmp(tokens->data[*idx], "id"))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "expected id qualifier");
	++(*idx);
	if (*idx >= tokens->count)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "missing mark value");
	uint32_t value;
	if (parse_uint32(tokens->data[*idx], &value))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "invalid mark value");
	++(*idx);
	mark = rte_zmalloc_socket("flow_mark", sizeof(*mark), 0,
				   parser->socket_id);
	if (!mark)
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "failed to allocate mark action");
	mark->id = value;
	action->type = RTE_FLOW_ACTION_TYPE_MARK;
	action->conf = mark;
	return 0;
}

static int
parse_action_queue(struct rte_flow_parser *parser, struct token_list *tokens,
	           size_t *idx, struct rte_flow_action *action,
	           struct rte_flow_error *error)
{
	struct rte_flow_action_queue *queue;
	if (*idx >= tokens->count)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "expected queue qualifier");
	if (strcasecmp(tokens->data[*idx], "index"))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "expected queue index");
	++(*idx);
	if (*idx >= tokens->count)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "missing queue index value");
	uint32_t value;
	if (parse_uint32(tokens->data[*idx], &value))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "invalid queue index value");
	++(*idx);
	queue = rte_zmalloc_socket("flow_queue", sizeof(*queue), 0,
				    parser->socket_id);
	if (!queue)
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "failed to allocate queue action");
	queue->index = value;
	action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action->conf = queue;
	return 0;
}

static int
parse_action_flag(struct rte_flow_action *action)
{
	action->type = RTE_FLOW_ACTION_TYPE_FLAG;
	action->conf = NULL;
	return 0;
}

static int
parse_action_jump(struct rte_flow_parser *parser, struct token_list *tokens,
	           size_t *idx, struct rte_flow_action *action,
	           struct rte_flow_error *error)
{
	struct rte_flow_action_jump *jump;
	if (*idx >= tokens->count)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "expected group qualifier");
	if (strcasecmp(tokens->data[*idx], "group"))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "expected jump group");
	++(*idx);
	if (*idx >= tokens->count)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "missing jump group id");
	uint32_t value;
	if (parse_uint32(tokens->data[*idx], &value))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "invalid jump group id");
	++(*idx);
	jump = rte_zmalloc_socket("flow_jump", sizeof(*jump), 0,
				    parser->socket_id);
	if (!jump)
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				   "failed to allocate jump action");
	jump->group = value;
	action->type = RTE_FLOW_ACTION_TYPE_JUMP;
	action->conf = jump;
	return 0;
}

static int
parse_actions_section(struct rte_flow_parser *parser, struct token_list *tokens,
		       size_t *idx, struct rte_flow_parse_result *result,
		       struct rte_flow_error *error)
{
	uint32_t count = 0;
	struct rte_flow_action *actions;

	actions = rte_zmalloc_socket("flow_actions",
			 (parser->max_actions + 1) * sizeof(*actions),
			 0, parser->socket_id);
	if (!actions)
		return error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "failed to allocate actions array");

	while (*idx < tokens->count) {
		char *token = tokens->data[*idx];
		if (!strcasecmp(token, "/")) {
			++(*idx);
			continue;
		}
		if (!strcasecmp(token, "end")) {
			++(*idx);
			goto actions_done;
		}
		int cap = ensure_capacity(parser->max_actions, count, error,
			"too many actions");
		if (cap) {
			actions_cleanup(actions, count);
			rte_free(actions);
			return cap;
		}
		++(*idx);
		if (!strcasecmp(token, "drop")) {
			parse_action_drop(&actions[count]);
		} else if (!strcasecmp(token, "mark")) {
			if (parse_action_mark(parser, tokens, idx, &actions[count], error)) {
				actions_cleanup(actions, count);
				rte_free(actions);
				return -1;
			}
		} else if (!strcasecmp(token, "queue")) {
			if (parse_action_queue(parser, tokens, idx, &actions[count], error)) {
				actions_cleanup(actions, count);
				rte_free(actions);
				return -1;
			}
		} else if (!strcasecmp(token, "flag")) {
			parse_action_flag(&actions[count]);
		} else if (!strcasecmp(token, "jump")) {
			if (parse_action_jump(parser, tokens, idx, &actions[count], error)) {
				actions_cleanup(actions, count);
				rte_free(actions);
				return -1;
			}
		} else {
			actions_cleanup(actions, count);
			rte_free(actions);
			return error_set(error, ENOTSUP,
					 RTE_FLOW_ERROR_TYPE_ACTION,
					 "unsupported action token");
		}
		++count;
	}
	actions_cleanup(actions, count);
	rte_free(actions);
	return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
			 "actions section missing end");

actions_done:
	actions[count].type = RTE_FLOW_ACTION_TYPE_END;
	result->actions = actions;
	result->actions_count = count;
	return 0;
}

static void
init_result(struct rte_flow_parse_result *result)
{
	if (!result)
		return;
	memset(result, 0, sizeof(*result));
}

__rte_experimental
struct rte_flow_parser *
rte_flow_parser_create(const struct rte_flow_parse_attr *attr,
			    struct rte_flow_error *error)
{
	struct rte_flow_parser *parser;

	(void)error;
	parser = rte_zmalloc_socket("rte_flow_parser",
			 sizeof(*parser), 0,
			 attr ? (int)attr->socket_id : SOCKET_ID_ANY);
	if (!parser) {
		if (error)
			return (struct rte_flow_parser *)
				(uintptr_t)rte_flow_error_set(error, ENOMEM,
					RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					NULL, "failed to allocate parser");
		return NULL;
	}
	parser_defaults(parser, attr);
	return parser;
}

__rte_experimental
int
rte_flow_parser_reset(struct rte_flow_parser *parser,
		       struct rte_flow_error *error)
{
	(void)parser;
	(void)error;
	return 0;
}

static int
parse_rule_tokens(struct rte_flow_parser *parser, struct token_list *tokens,
		   struct rte_flow_parse_result *result,
		   struct rte_flow_error *error)
{
	size_t idx = 0;
	uint32_t value;

	if (tokens->count < 6)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "incomplete flow command");
	if (strcasecmp(tokens->data[idx++], "flow"))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "expected flow keyword");
	if (strcasecmp(tokens->data[idx++], "create"))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "expected create keyword");
	if (parse_uint32(tokens->data[idx++], &value))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "invalid port identifier");
	result->port_id = (uint16_t)value;
	while (idx < tokens->count) {
		char *token = tokens->data[idx];
		if (!strcasecmp(token, "pattern")) {
			++idx;
			break;
		}
		if (!strcasecmp(token, "group")) {
			++idx;
			if (idx >= tokens->count)
				return error_set(error, EINVAL,
						 RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
						 "missing group value");
			if (parse_uint32(tokens->data[idx++], &value))
				return error_set(error, EINVAL,
						 RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
						 "invalid group value");
			result->attr.group = value;
			continue;
		}
		if (!strcasecmp(token, "priority")) {
			++idx;
			if (idx >= tokens->count)
				return error_set(error, EINVAL,
						 RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY,
						 "missing priority value");
			if (parse_uint32(tokens->data[idx++], &value))
				return error_set(error, EINVAL,
						 RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY,
						 "invalid priority value");
			result->attr.priority = value;
			continue;
		}
		if (!strcasecmp(token, "ingress")) {
			result->attr.ingress = 1;
			++idx;
			continue;
		}
		if (!strcasecmp(token, "egress")) {
			result->attr.egress = 1;
			++idx;
			continue;
		}
		if (!strcasecmp(token, "transfer")) {
			result->attr.transfer = 1;
			++idx;
			continue;
		}
		return error_set(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ATTR,
				 "unsupported attribute token");
	}
	if (idx >= tokens->count)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
				   "missing pattern section");
	if (parse_pattern_section(parser, tokens, &idx, result, error))
		return -1;
	if (idx >= tokens->count)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
				   "missing actions section");
	if (strcasecmp(tokens->data[idx], "actions"))
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
				   "expected actions keyword");
	++idx;
	if (parse_actions_section(parser, tokens, &idx, result, error)) {
		rte_flow_parser_pattern_free(parser, result->pattern);
		result->pattern = NULL;
		result->pattern_count = 0;
		return -1;
	}
	return 0;
}

static int
parse_pattern_tokens(struct rte_flow_parser *parser, struct token_list *tokens,
		    struct rte_flow_item **pattern, uint32_t *count,
		    struct rte_flow_error *error)
{
	size_t idx = 0;
	struct rte_flow_parse_result tmp;
	init_result(&tmp);
	if (idx < tokens->count && !strcasecmp(tokens->data[idx], "pattern"))
		++idx;
	if (parse_pattern_section(parser, tokens, &idx, &tmp, error))
		return -1;
	*pattern = tmp.pattern;
	if (count)
		*count = tmp.pattern_count;
	return 0;
}

static int
parse_actions_tokens(struct rte_flow_parser *parser, struct token_list *tokens,
		    struct rte_flow_action **actions, uint32_t *count,
		    struct rte_flow_error *error)
{
	size_t idx = 0;
	struct rte_flow_parse_result tmp;
	init_result(&tmp);
	if (idx < tokens->count && !strcasecmp(tokens->data[idx], "actions"))
		++idx;
	if (parse_actions_section(parser, tokens, &idx, &tmp, error))
		return -1;
	*actions = tmp.actions;
	if (count)
		*count = tmp.actions_count;
	return 0;
}

__rte_experimental
int
rte_flow_parser_rule(struct rte_flow_parser *parser,
		      const char *input,
		      struct rte_flow_parse_result *result,
		      struct rte_flow_error *error)
{
	struct token_list tokens = {0};
	int ret;

	if (!parser || !input || !result)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "invalid parser arguments");
	init_result(result);
	ret = tokenize(parser, input, &tokens);
	if (ret) {
		token_list_reset(&tokens);
		return error_set(error, -ret, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "tokenization failed");
	}
	ret = parse_rule_tokens(parser, &tokens, result, error);
	token_list_reset(&tokens);
	return ret;
}

__rte_experimental
int
rte_flow_parser_pattern(struct rte_flow_parser *parser,
		 const char *pattern_str,
		 struct rte_flow_item **pattern_out,
		 uint32_t *pattern_count,
		 struct rte_flow_error *error)
{
	struct token_list tokens = {0};
	int ret;

	if (!parser || !pattern_str || !pattern_out)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "invalid pattern arguments");
	*pattern_out = NULL;
	if (pattern_count)
		*pattern_count = 0;
	ret = tokenize(parser, pattern_str, &tokens);
	if (ret) {
		token_list_reset(&tokens);
		return error_set(error, -ret, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "tokenization failed");
	}
	ret = parse_pattern_tokens(parser, &tokens, pattern_out, pattern_count,
				error);
	token_list_reset(&tokens);
	if (ret && pattern_count)
		*pattern_count = 0;
	return ret;
}

__rte_experimental
int
rte_flow_parser_actions(struct rte_flow_parser *parser,
		 const char *actions_str,
		 struct rte_flow_action **actions_out,
		 uint32_t *actions_count,
		 struct rte_flow_error *error)
{
	struct token_list tokens = {0};
	int ret;

	if (!parser || !actions_str || !actions_out)
		return error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "invalid actions arguments");
	*actions_out = NULL;
	if (actions_count)
		*actions_count = 0;
	ret = tokenize(parser, actions_str, &tokens);
	if (ret) {
		token_list_reset(&tokens);
		return error_set(error, -ret, RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
				   "tokenization failed");
	}
	ret = parse_actions_tokens(parser, &tokens, actions_out, actions_count,
				error);
	token_list_reset(&tokens);
	if (ret && actions_count)
		*actions_count = 0;
	return ret;
}

__rte_experimental
void
rte_flow_parser_destroy(struct rte_flow_parser *parser)
{
	if (!parser)
		return;
	rte_free(parser);
}

__rte_experimental
void
rte_flow_parser_pattern_free(struct rte_flow_parser *parser __rte_unused,
		            struct rte_flow_item *pattern)
{
	if (!pattern)
		return;
	for (struct rte_flow_item *item = pattern;
	     item->type != RTE_FLOW_ITEM_TYPE_END;
	     ++item) {
		rte_free((void *)(uintptr_t)item->spec);
		rte_free((void *)(uintptr_t)item->mask);
		rte_free((void *)(uintptr_t)item->last);
	}
	rte_free(pattern);
}

__rte_experimental
void
rte_flow_parser_actions_free(struct rte_flow_parser *parser __rte_unused,
		            struct rte_flow_action *actions)
{
	if (!actions)
		return;
	for (struct rte_flow_action *action = actions;
	     action->type != RTE_FLOW_ACTION_TYPE_END;
	     ++action)
		rte_free((void *)(uintptr_t)action->conf);
	rte_free(actions);
}

__rte_experimental
void
rte_flow_parse_result_free(struct rte_flow_parser *parser,
			      struct rte_flow_parse_result *result)
{
	if (!result)
		return;
	rte_flow_parser_pattern_free(parser, result->pattern);
	rte_flow_parser_actions_free(parser, result->actions);
	result->pattern = NULL;
	result->pattern_count = 0;
	result->actions = NULL;
	result->actions_count = 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_create, 25.11)
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_reset, 25.11)
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_rule, 25.11)
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_pattern, 25.11)
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_actions, 25.11)
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_destroy, 25.11)
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_pattern_free, 25.11)
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parser_actions_free, 25.11)
RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_flow_parse_result_free, 25.11)
