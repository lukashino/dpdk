/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdio.h>
#include <string.h>

#include <cmdline_parse.h>
#include <cmdline_parse_string.h>

#include <rte_flow_parser.h>

struct flow_parser_cmd {
	cmdline_fixed_string_t cmd;
	cmdline_multi_string_t args;
};

static int
flow_parser_run_str(const char *cmd, const char *args)
{
	char line[4096];
	int len;

	if (!cmd)
		return -EINVAL;
	len = snprintf(line, sizeof(line), "%s%s%s",
		       cmd,
		       (args && args[0]) ? " " : "",
		       args ? args : "");
	if (len < 0 || len >= (int)sizeof(line))
		return -ENOBUFS;
	return rte_flow_parser_run(NULL, line);
}

static void
cmd_flow_parser_parsed(void *parsed_result, struct cmdline *cl, void *data)
{
	struct flow_parser_cmd *res = parsed_result;
	int ret;

	RTE_SET_USED(cl);
	RTE_SET_USED(data);
	ret = flow_parser_run_str("flow", res->args);
	if (ret)
		printf("Flow parser error: %d\n", ret);
}

static void
cmd_set_raw_parsed(void *parsed_result, struct cmdline *cl, void *data)
{
	struct flow_parser_cmd *res = parsed_result;
	int ret;

	RTE_SET_USED(cl);
	RTE_SET_USED(data);
	ret = flow_parser_run_str("set", res->args);
	if (ret)
		printf("Flow parser error: %d\n", ret);
}

static void
cmd_show_set_raw_parsed(void *parsed_result, struct cmdline *cl, void *data)
{
	struct flow_parser_cmd *res = parsed_result;
	int ret;

	RTE_SET_USED(cl);
	RTE_SET_USED(data);
	ret = flow_parser_run_str("show", res->args);
	if (ret)
		printf("Flow parser error: %d\n", ret);
}

static cmdline_parse_token_string_t cmd_flow_cmd =
	TOKEN_STRING_INITIALIZER(struct flow_parser_cmd, cmd, "flow");
static cmdline_parse_token_string_t cmd_set_cmd =
	TOKEN_STRING_INITIALIZER(struct flow_parser_cmd, cmd, "set");
static cmdline_parse_token_string_t cmd_show_cmd =
	TOKEN_STRING_INITIALIZER(struct flow_parser_cmd, cmd, "show");
static cmdline_parse_token_string_t cmd_flow_args =
	TOKEN_STRING_INITIALIZER(struct flow_parser_cmd, args,
				 TOKEN_STRING_MULTI);

cmdline_parse_inst_t cmd_flow = {
	.f = cmd_flow_parser_parsed,
	.data = NULL,
	.help_str = "flow ...",
	.tokens = {
		(void *)&cmd_flow_cmd,
		(void *)&cmd_flow_args,
		NULL,
	},
};

cmdline_parse_inst_t cmd_set_raw = {
	.f = cmd_set_raw_parsed,
	.data = NULL,
	.help_str = "set raw_encap/raw_decap/sample/ipv6_ext_* ...",
	.tokens = {
		(void *)&cmd_set_cmd,
		(void *)&cmd_flow_args,
		NULL,
	},
};

cmdline_parse_inst_t cmd_show_set_raw = {
	.f = cmd_show_set_raw_parsed,
	.data = NULL,
	.help_str = "show raw_encap/raw_decap <index>",
	.tokens = {
		(void *)&cmd_show_cmd,
		(void *)&cmd_flow_args,
		NULL,
	},
};

cmdline_parse_inst_t cmd_show_set_raw_all = {
	.f = cmd_show_set_raw_parsed,
	.data = NULL,
	.help_str = "show raw_encap/raw_decap all",
	.tokens = {
		(void *)&cmd_show_cmd,
		(void *)&cmd_flow_args,
		NULL,
	},
};
