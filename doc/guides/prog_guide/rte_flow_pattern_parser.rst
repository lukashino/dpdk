..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2024 Open vSwitch community

Flow Pattern String Parser
==========================

Overview
--------

The rte_flow pattern parser library provides a public API for parsing
human-readable rte_flow pattern strings into ``struct rte_flow_item[]``
arrays. This allows external applications (such as Suricata IDS) to
reuse the same pattern syntax as testpmd without linking to or
duplicating testpmd code.

The input uses testpmd flow pattern syntax::

    eth / ipv4 dst is 192.168.1.1 / tcp dst is 80 / end

The output is a heap-allocated, self-contained ``struct rte_flow_item[]``
array terminated by ``RTE_FLOW_ITEM_TYPE_END``.

Motivation
----------

Before this library, the only way to parse rte_flow pattern strings was
through testpmd's internal ``flow_parse()`` function, which depends on
testpmd-specific data structures (``struct buffer``, port IDs, etc.).
External applications that wanted to translate human-readable flow rules
into rte_flow API calls had to either:

* Duplicate the pattern parsing logic from testpmd, creating a
  maintenance burden as new item types are added.
* Use a custom parser that may diverge from testpmd's syntax.

The pattern parser library solves this by providing a clean, reusable
API that is part of the ethdev library.

API Usage
---------

Basic Workflow
~~~~~~~~~~~~~~

.. code-block:: c

   #include <rte_flow_pattern_parser.h>

   /* Create a parser context (reusable across multiple parses). */
   struct rte_flow_pattern_parser *parser;
   parser = rte_flow_pattern_parser_create();

   /* Parse a pattern string. */
   struct rte_flow_item *pattern;
   struct rte_flow_error error;
   int ret;

   ret = rte_flow_pattern_parse(parser,
       "eth / ipv4 dst is 192.168.1.1 / tcp dst is 80 / end",
       &pattern, &error);
   if (ret != 0) {
       fprintf(stderr, "Parse error: %s\\n", error.message);
       /* handle error */
   }

   /* Use the pattern with rte_flow_create(), rte_flow_validate(), etc. */
   /* ... */

   /* Free the pattern when done. */
   rte_flow_pattern_free(pattern);

   /* Destroy the parser when no longer needed. */
   rte_flow_pattern_parser_destroy(parser);

Pattern String Syntax
~~~~~~~~~~~~~~~~~~~~~

The pattern string format matches testpmd's ``flow create`` pattern syntax:

* Items are separated by ``/`` with surrounding spaces.
* Each item starts with a type name (e.g., ``eth``, ``ipv4``, ``tcp``).
* Field values are specified with ``<field> is <value>`` for exact match.
* Alternative modifiers: ``spec``, ``mask``, ``last``, ``prefix``.
* The pattern must end with ``end``.

Examples::

    eth / end
    eth / ipv4 dst is 192.168.1.1 / end
    eth / ipv4 src spec 10.0.0.0 src mask 255.0.0.0 / udp / end
    eth / vlan vid is 100 / ipv4 / tcp dst is 443 / end

Field Specification Modifiers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* ``is`` - Match value exactly (sets both spec and mask).
* ``spec`` - Set the spec value (match per configured mask).
* ``mask`` - Set the mask value explicitly.
* ``last`` - Set the last value (upper bound of a range).
* ``prefix`` - Generate a mask from a prefix length (e.g., ``prefix 24``
  generates ``255.255.255.0``).

Memory Management
-----------------

The ``rte_flow_pattern_parse()`` function returns a self-contained
allocation. The ``struct rte_flow_item`` array and all data referenced
by the ``spec``, ``mask``, and ``last`` pointers live in a single
contiguous memory block allocated with ``rte_malloc()``.

A single call to ``rte_flow_pattern_free()`` releases the entire
allocation. After this call, all pointers into the pattern (including
item spec/mask/last pointers) become invalid.

Thread Safety
-------------

Each ``struct rte_flow_pattern_parser`` context is independent. Multiple
threads may use separate parser contexts concurrently without any
synchronization. A single parser context must not be used from multiple
threads simultaneously.

Completion API
--------------

For interactive tools that want tab-completion, the
``rte_flow_pattern_complete()`` function provides token suggestions
for a partial pattern string.

.. code-block:: c

   const char *completions[64];
   int count;

   count = rte_flow_pattern_complete(parser, "eth / ip",
                                     completions, 64);
   /* completions[] now contains "ipv4", "ipv6", etc. */

Supported Item Types
--------------------

The parser supports all statically defined rte_flow item types,
including but not limited to:

* Layer 2: ``eth``, ``vlan``
* Layer 3: ``ipv4``, ``ipv6``, ``arp_eth_ipv4``
* Layer 4: ``tcp``, ``udp``, ``sctp``, ``icmp``, ``icmp6``
* Tunneling: ``vxlan``, ``gre``, ``gtp``, ``geneve``, ``mpls``, ``nvgre``
* Misc: ``any``, ``void``, ``mark``, ``meta``, ``tag``

See the ``rte_flow_pattern_parser.c`` source for the complete list
of supported item types and their fields.
