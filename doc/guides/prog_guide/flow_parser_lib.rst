..  SPDX-License-Identifier: BSD-3-Clause

Flow Parser Library
===================

Overview
--------

The flow parser library factors out the complete testpmd ``flow`` CLI grammar
into a reusable component. Applications can feed testpmd-style commands such as
``flow create ...`` or ``set raw_encap ...`` and receive fully-populated
``rte_flow`` structures along with callbacks for execution. This makes it
possible to:

* Accept user input in the familiar testpmd syntax.
* Reuse the comprehensive parsing logic (attributes, patterns, actions,
  templates, indirect actions, tunnel helpers, and raw encap/decap helpers).
* Integrate with application-specific control planes via callback tables.

The API surface lives in ``rte_flow_parser.h`` and is part of the installed
headers. The library is built as ``librte_flow_parser``.

Building and Linking
--------------------

Add the dependency to your Meson target::

  deps += ['flow_parser']

Include the header in your code::

  #include <rte_flow_parser.h>

The demo application ``app/demo_flow_parser`` shows a minimal build rule and
usage. Build it with::

  ninja -C build app/dpdk-demo_flow_parser

Parser Lifecycle
----------------

Create and destroy parser instances:

* ``rte_flow_parser_create(const struct rte_flow_parser_ops *ops, void *userdata)``
  creates an instance bound to a pair of callback tables and an opaque
  ``userdata`` pointer returned to every callback.
* ``rte_flow_parser_destroy()`` frees the instance.
* ``rte_flow_parser_set_default_ops()`` sets the callback tables for the global
  default parser used when ``parser == NULL`` in ``rte_flow_parser_parse()``.

The parser keeps internal state (defaults, temporary buffers, cmdline tokens)
inside the handle. Instances are not inherently thread-safe; guard concurrent
parsing with external synchronization or use separate instances per thread.

Parsing Commands
----------------

``int rte_flow_parser_parse(struct rte_flow_parser *parser, const char *src,
struct rte_flow_parser_output *result, size_t result_size)`` accepts a string
containing one or more commands. Whitespace or newlines may separate commands.

Output is written into the caller-provided buffer. The buffer must be at least
``sizeof(struct rte_flow_parser_output)`` and must also leave headroom for
embedded pattern/action data (the parser appends specs/masks/confs inside the
same buffer). Allocate a few kilobytes (e.g. 4–8 KiB) for typical commands;
``-ENOBUFS`` is returned if the buffer is too small.

On success the ``result`` fields describe the parsed command:

* ``command`` enumerates the operation (validate, create, destroy, template
  operations, indirect actions, set raw*, etc.).
* ``port``, ``queue``, and ``args.*`` carry the parsed attributes, patterns,
  actions, masks, user IDs, template IDs, and helper data.
* ``pattern``/``actions`` point into the caller buffer; copy or consume them
  before parsing the next command.

``int rte_flow_parser_run(struct rte_flow_parser *parser, const char *src)``
is a convenience wrapper that parses and immediately dispatches the command
through the installed ``command_ops`` callbacks.

Callback Model
--------------

Two callback tables are provided at creation time:

* ``struct rte_flow_parser_query_ops`` supplies read-only helpers used during
  parsing and completion: port validation, queue/template counts, default
  encapsulation templates, raw encap/decap caches,
  IPv6 extension caches, sample action caches, flex item handles, etc. Missing
  callbacks fall back to safe defaults (for example, built-in VXLAN/NVGRE/L2/
  MPLS encap templates). RSS type strings come from the ethdev global table
  (``rte_eth_rss_type_info_get()``).
* ``struct rte_flow_parser_command_ops`` is invoked when a command is accepted
  by the cmdline integration helpers. ``rte_flow_parser_parse()`` only parses
  and never dispatches callbacks. Typical command implementations map directly
  to ``rte_flow`` or application-specific control plane functions:
  ``flow_validate``, ``flow_create``, destroy/update variants,
  table/template management, indirect actions, hash calculation, tunnel
  helpers, and the ``set raw*/set sample/set ipv6_ext_*`` helpers.

Implement only the callbacks your application needs; unused hooks may be NULL.
The parser never stores raw encap/decap/sample/IPv6-ext payloads internally;
the corresponding ``set_*`` callbacks must persist data if the application
expects later lookup.

Lightweight Parsing Helpers
---------------------------

For applications that only need fragments of a flow rule, convenience helpers
parse small snippets without creating a parser instance:

* ``rte_flow_parser_parse_attr_str()`` parses only flow attributes.
* ``rte_flow_parser_parse_pattern_str()`` parses only a pattern list and
  returns a pointer to the resulting ``struct rte_flow_item`` array plus its
  length.
* ``rte_flow_parser_parse_actions_str()`` parses only an actions list and
  returns a pointer to the resulting ``struct rte_flow_action`` array plus its
  length.

These helpers allocate and manage internal storage per thread; the returned
pointers remain valid until the next helper call on the same thread.

Defaults and Tunables
---------------------

If the application does not supply specific query callbacks, the parser uses
built-in defaults:

* VXLAN/NVGRE/L2/MPLS* encap/decap templates for actions.
* RSS type string table from ethdev (``rte_eth_rss_type_info_get()``) and
  default hash fields (``RTE_ETH_RSS_IP``).
* Raw encap/decap, IPv6 extension, and sample action caches return empty/null
  unless provided by callbacks.

Applications can override encapsulation templates, caches, and hash fields by
implementing the corresponding ``*_conf_get`` callbacks in
``rte_flow_parser_query_ops``.

Example Usage
-------------

``app/demo_flow_parser/demo_flow_parser.c`` demonstrates minimal usage:

* Provide ``port_validate`` and ``flow_create`` callbacks.
* Create a parser and pass it a series of flow commands.
* Inspect ``struct rte_flow_parser_output`` for parsed patterns/actions or let
  ``flow_create`` consume them directly.

Run the demo::

  ./build/app/dpdk-demo_flow_parser

The output lists each command and the number of parsed pattern/action entries,
proving the parser is decoupled from testpmd and usable in standalone
applications.
