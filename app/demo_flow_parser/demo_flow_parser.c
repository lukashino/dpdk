/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <rte_common.h>
#include <rte_flow_parser.h>

static int stub_port_validate(uint16_t port_id, bool warn, void *userdata)
{
	(void)warn; (void)userdata;
	return port_id != 0; /* only port 0 allowed */
}

static void stub_flow_create(uint16_t port_id, const struct rte_flow_attr *attr,
			 const struct rte_flow_item pattern[],
			 const struct rte_flow_action actions[],
			 const struct rte_flow_parser_tunnel_ops *ops,
			 uintptr_t user_id, void *userdata)
{
	(void)attr; (void)pattern; (void)actions; (void)ops; (void)userdata;
	printf("flow_create called for port %u user_id=%lu\n",
	       port_id, (unsigned long)user_id);
}

static const struct rte_flow_parser_query_ops stub_query_ops = {
	.port_validate = stub_port_validate,
};

static const struct rte_flow_parser_command_ops stub_cmd_ops = {
	.flow_create = stub_flow_create,
};

static const struct rte_flow_parser_ops stub_ops = {
	.query = &stub_query_ops,
	.command = &stub_cmd_ops,
};

static void
run_case(struct rte_flow_parser *p, const char *cmd)
{
	uint8_t outbuf[4096];
	struct rte_flow_parser_output *out = (void *)outbuf;
	int ret;

	memset(outbuf, 0, sizeof(outbuf));
	ret = rte_flow_parser_parse(p, cmd, out, sizeof(outbuf));
	if (ret == 0) {
		printf("[OK]  %s\n", cmd);
		printf("      port=%u patterns=%u actions=%u\n",
		       out->port, out->args.vc.pattern_n,
		       out->args.vc.actions_n);
	} else {
		printf("[ERR %d] %s\n", ret, cmd);
	}
}

int main(void)
{
	struct rte_flow_parser *p = rte_flow_parser_create(&stub_ops, NULL);
	static const char *cases[] = {
		"flow create 0 ingress pattern eth / end actions drop / end",
		"flow create 0 ingress pattern eth dst is 90:61:ae:fd:41:43 / end actions queue index 1 / end",
		"flow create 0 ingress pattern icmp type is 3 code is 3 / end actions queue index 1 / end",
		"flow create 0 ingress pattern eth / ipv4 src is 192.168.0.1 / udp / end actions port_id id 1 / end",
		"flow create 0 ingress pattern eth / ipv4 src is 192.168.0.1 / udp / end actions set_ipv4_src ipv4_addr 172.16.0.10 / end",
		"flow create 0 ingress pattern eth / ipv4 src is 192.168.0.1 / udp / end actions age timeout 128 / end",
	};
	unsigned int i;

	if (!p) {
		fprintf(stderr, "failed to create parser\n");
		return 1;
	}
	for (i = 0; i < RTE_DIM(cases); i++)
		run_case(p, cases[i]);
	rte_flow_parser_destroy(p);
	return 0;
}
