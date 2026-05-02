"""Tiny tag-based template engine.

Askama-shape minimal subset for v0.7. Supports the three tags
that cover ~90% of HTML / email / config templating use:

* ``{{ name }}`` — variable substitution (HTML-escaped by
  default; ``{{ name | safe }}`` opts out).
* ``{% if name %}...{% endif %}`` — boolean conditional;
  ``name`` is truthy iff non-empty (matches Jinja2 semantics
  for ``string`` truthiness which is the most-common-by-far
  use).
* ``{% for x in name %}...{% endfor %}`` — loop over a
  list-typed context value; each iteration shadows ``x`` for
  the body.

Out of scope for v0.7 (deferred to v0.8 per design-0.7.mdc § 273):

- Template inheritance / blocks (``{% block %}`` /
  ``{% extends %}``).
- Filters beyond ``| safe`` (``| upper``, ``| length``, etc.).
- ``{% else %}`` branches.
- Whitespace control flags (``{%- ... -%}``).
- Macros / includes.

Type model:

The context is a ``Context`` struct with two flat maps —
``strings: Dict[String, String]`` for ``{{ var }}`` /
conditional truthiness, ``lists: Dict[String, List[String]]``
for ``{% for %}`` iteration. The render pass walks the parsed
tree and resolves names against the strings map first, then
the lists map (for ``{% if %}``: a non-empty list is also
truthy). Loop variables are pushed onto the strings map for
the duration of one iteration via a frame stack.

Why a parsed tree and not a single string-walk:

- ``{% for %}`` requires knowing where the matching ``{% endfor %}``
  is so we can re-render the body N times.
- ``{% if %}`` requires the same for skipping a false branch.
- The parser runs once per :func:`Template.compile` and the
  parsed tree is cached on the ``Template`` struct, so the
  per-render cost is just the tree walk + variable lookups.
- A future ``v0.8`` block-inheritance upgrade is a tree-rewrite,
  not a re-parse.

Performance:

The tree walk is O(N) in the size of the rendered output plus
the number of variable lookups. Variable lookups are O(1)
``Dict`` hits. HTML escape is a single-pass byte loop allocating
one growing buffer. There is no pre-rendered "compiled function"
shape (askama / sailfish do this with codegen at compile time);
flare's reactor latency budget is dominated by network IO not
template render, so the v0.7 cut keeps the parser-tree-walker
simple.
"""

from .request import Request


# ── HTML escape ─────────────────────────────────────────────────────────────


def html_escape(s: String) -> String:
    """Escape ``s`` for safe inclusion in HTML body text or
    attribute values, per OWASP XSS Prevention Cheat Sheet rule
    #1 (body) + rule #2 (attribute). Replaces the five
    HTML-significant bytes:

    - ``&`` → ``&amp;``
    - ``<`` → ``&lt;``
    - ``>`` → ``&gt;``
    - ``"`` → ``&quot;``
    - ``'`` → ``&#x27;``
    """
    var n = s.byte_length()
    if n == 0:
        return String("")
    var out = String(capacity=n + 8)
    var p = s.unsafe_ptr()
    for i in range(n):
        var b = Int(p[i])
        if b == ord("&"):
            out += "&amp;"
        elif b == ord("<"):
            out += "&lt;"
        elif b == ord(">"):
            out += "&gt;"
        elif b == ord('"'):
            out += "&quot;"
        elif b == ord("'"):
            out += "&#x27;"
        else:
            out += chr(b)
    return out^


# ── Node types ──────────────────────────────────────────────────────────────


comptime _NODE_TEXT: Int = 0
comptime _NODE_VAR: Int = 1
comptime _NODE_VAR_SAFE: Int = 2
comptime _NODE_IF: Int = 3
comptime _NODE_FOR: Int = 4


@fieldwise_init
struct TemplateNode(Copyable, Movable):
    """Single node in the parsed template tree.

    ``kind`` is one of the ``_NODE_*`` constants above. The other
    fields are populated per-kind:

    - ``_NODE_TEXT``: ``text`` holds the raw bytes; everything
      else is empty.
    - ``_NODE_VAR``: ``name`` holds the variable name (HTML-
      escaped on render); everything else empty.
    - ``_NODE_VAR_SAFE``: ``name`` holds the variable name
      (rendered verbatim); everything else empty.
    - ``_NODE_IF``: ``name`` is the truthy-test variable;
      ``children`` is the body to render if truthy.
    - ``_NODE_FOR``: ``loop_var`` is the per-iteration name,
      ``name`` is the iterable variable, ``children`` is the
      body rendered once per element.
    """

    var kind: Int
    var text: String
    var name: String
    var loop_var: String
    var children: List[TemplateNode]


# ── Context ────────────────────────────────────────────────────────────────


@fieldwise_init
struct TemplateContext(Copyable, Defaultable, Movable):
    """Variable bag for :func:`Template.render`.

    Two flat maps:

    - ``strings`` — name → value for ``{{ var }}`` substitution
      and ``{% if var %}`` truthiness.
    - ``lists`` — name → ``List[String]`` for ``{% for x in
      var %}`` iteration. A non-empty list is also truthy
      under ``{% if %}``.
    """

    var strings: Dict[String, String]
    var lists: Dict[String, List[String]]

    def __init__(out self):
        self.strings = Dict[String, String]()
        self.lists = Dict[String, List[String]]()

    def set(mut self, name: String, value: String):
        """Add or overwrite a string-typed binding."""
        self.strings[name.copy()] = value.copy()

    def set_list(mut self, name: String, value: List[String]):
        """Add or overwrite a list-typed binding."""
        self.lists[name.copy()] = value.copy()


# ── Parser ─────────────────────────────────────────────────────────────────


def _parse_segment(
    src: String, mut pos: Int, until_tags: List[String]
) raises -> List[TemplateNode]:
    """Parse template body from ``pos`` until one of
    ``until_tags`` is encountered. Returns the parsed nodes;
    leaves ``pos`` pointing at the first byte of the matched
    end tag (or ``len(src)`` if EOF).

    ``until_tags`` is the set of opener-block-end tag-names this
    parse may legitimately stop on (e.g. ``["endif"]`` for
    inside an ``{% if %}`` body, or ``[]`` for the top level).
    Any control tag whose name is not in ``until_tags`` is
    treated as a fresh nested control block.
    """
    var out = List[TemplateNode]()
    var n = src.byte_length()
    var p = src.unsafe_ptr()
    while pos < n:
        # Look for the next ``{`` opener.
        var open_pos = -1
        var i = pos
        while i + 1 < n:
            if Int(p[i]) == ord("{") and (
                Int(p[i + 1]) == ord("{") or Int(p[i + 1]) == ord("%")
            ):
                open_pos = i
                break
            i += 1
        if open_pos < 0:
            # No more tags — emit the remainder as text.
            if pos < n:
                var t = String(capacity=n - pos)
                for j in range(pos, n):
                    t += chr(Int(p[j]))
                out.append(
                    TemplateNode(
                        _NODE_TEXT,
                        t^,
                        String(""),
                        String(""),
                        List[TemplateNode](),
                    )
                )
            pos = n
            return out^
        if open_pos > pos:
            var t = String(capacity=open_pos - pos)
            for j in range(pos, open_pos):
                t += chr(Int(p[j]))
            out.append(
                TemplateNode(
                    _NODE_TEXT,
                    t^,
                    String(""),
                    String(""),
                    List[TemplateNode](),
                )
            )
        # We're now at ``{{`` or ``{%``.
        var second = Int(p[open_pos + 1])
        if second == ord("{"):
            # ``{{ name }}`` or ``{{ name | safe }}``.
            var close = _find_close(src, open_pos + 2, "}}")
            if close < 0:
                raise Error("template: unterminated {{...}} expression")
            var inside = _slice(src, open_pos + 2, close)
            var trimmed = _strip(inside)
            var safe = False
            var name_part = trimmed
            var pipe_off = _find_byte(trimmed, ord("|"))
            if pipe_off >= 0:
                var filt = _strip(
                    _slice(trimmed, pipe_off + 1, trimmed.byte_length())
                )
                if filt != String("safe"):
                    raise Error("template: only the | safe filter is supported")
                safe = True
                name_part = _strip(_slice(trimmed, 0, pipe_off))
            if name_part.byte_length() == 0:
                raise Error("template: empty variable name in {{...}}")
            var kind = _NODE_VAR_SAFE if safe else _NODE_VAR
            out.append(
                TemplateNode(
                    kind,
                    String(""),
                    name_part^,
                    String(""),
                    List[TemplateNode](),
                )
            )
            pos = close + 2
        else:
            # ``{% ... %}`` control tag.
            var close = _find_close(src, open_pos + 2, "%}")
            if close < 0:
                raise Error("template: unterminated {%...%} tag")
            var raw = _strip(_slice(src, open_pos + 2, close))
            pos = close + 2
            # Tokenise on whitespace.
            var tokens = _split_ws(raw)
            if len(tokens) == 0:
                raise Error("template: empty control tag")
            var head = tokens[0]
            if _matches(until_tags, head):
                # Stop tag; rewind pos to the start of the
                # tag so the caller can advance past it.
                pos = open_pos
                return out^
            if head == String("if"):
                if len(tokens) != 2:
                    raise Error("template: {% if NAME %} requires one operand")
                var children = _parse_segment(src, pos, _list("endif"))
                # _parse_segment leaves pos at the start of the
                # matched end tag; advance past it now.
                pos = _skip_tag(src, pos, "endif")
                out.append(
                    TemplateNode(
                        _NODE_IF,
                        String(""),
                        tokens[1].copy(),
                        String(""),
                        children^,
                    )
                )
            elif head == String("for"):
                if len(tokens) != 4 or tokens[2] != String("in"):
                    raise Error(
                        "template: {% for X in Y %} required, got " + raw
                    )
                var loop_v = tokens[1].copy()
                var iter_n = tokens[3].copy()
                var children = _parse_segment(src, pos, _list("endfor"))
                pos = _skip_tag(src, pos, "endfor")
                out.append(
                    TemplateNode(
                        _NODE_FOR,
                        String(""),
                        iter_n^,
                        loop_v^,
                        children^,
                    )
                )
            elif head == String("endif") or head == String("endfor"):
                raise Error("template: unmatched closing tag " + head)
            else:
                raise Error("template: unknown tag " + head)
    return out^


def _list(s: String) -> List[String]:
    """Build a single-element ``List[String]`` literal — Mojo
    nightly's list-literal-from-comprehension story isn't
    consistent yet."""
    var out = List[String]()
    out.append(s)
    return out^


def _matches(tags: List[String], head: String) -> Bool:
    for i in range(len(tags)):
        if tags[i] == head:
            return True
    return False


def _find_close(src: String, start: Int, marker: String) -> Int:
    var n = src.byte_length()
    var p = src.unsafe_ptr()
    var m = marker.byte_length()
    var mp = marker.unsafe_ptr()
    var i = start
    while i + m <= n:
        var hit = True
        for j in range(m):
            if p[i + j] != mp[j]:
                hit = False
                break
        if hit:
            return i
        i += 1
    return -1


def _find_byte(s: String, target: Int) -> Int:
    var n = s.byte_length()
    var p = s.unsafe_ptr()
    for i in range(n):
        if Int(p[i]) == target:
            return i
    return -1


def _slice(s: String, start: Int, end: Int) -> String:
    var p = s.unsafe_ptr()
    var out = String(capacity=end - start)
    for i in range(start, end):
        out += chr(Int(p[i]))
    return out^


def _strip(s: String) -> String:
    var n = s.byte_length()
    var p = s.unsafe_ptr()
    var i = 0
    while i < n and (
        Int(p[i]) == ord(" ")
        or Int(p[i]) == ord("\t")
        or Int(p[i]) == ord("\n")
        or Int(p[i]) == ord("\r")
    ):
        i += 1
    var j = n - 1
    while j >= i and (
        Int(p[j]) == ord(" ")
        or Int(p[j]) == ord("\t")
        or Int(p[j]) == ord("\n")
        or Int(p[j]) == ord("\r")
    ):
        j -= 1
    return _slice(s, i, j + 1)


def _split_ws(s: String) -> List[String]:
    var out = List[String]()
    var n = s.byte_length()
    var p = s.unsafe_ptr()
    var i = 0
    while i < n:
        while i < n and (Int(p[i]) == ord(" ") or Int(p[i]) == ord("\t")):
            i += 1
        if i >= n:
            break
        var j = i
        while j < n and Int(p[j]) != ord(" ") and Int(p[j]) != ord("\t"):
            j += 1
        out.append(_slice(s, i, j))
        i = j
    return out^


def _skip_tag(src: String, pos: Int, tag: String) raises -> Int:
    """Given ``pos`` pointing at the start of a ``{% TAG %}``
    end tag (validated by ``_parse_segment``), return the byte
    position immediately after ``%}``."""
    var close = _find_close(src, pos + 2, "%}")
    if close < 0:
        raise Error("template: unterminated end-tag {% " + tag + " %}")
    return close + 2


# ── Renderer ───────────────────────────────────────────────────────────────


def _render_nodes(
    nodes: List[TemplateNode], mut ctx: TemplateContext
) raises -> String:
    var out = String(capacity=256)
    for i in range(len(nodes)):
        var node = nodes[i].copy()
        if node.kind == _NODE_TEXT:
            out += node.text
        elif node.kind == _NODE_VAR:
            out += html_escape(_lookup_string(ctx, node.name))
        elif node.kind == _NODE_VAR_SAFE:
            out += _lookup_string(ctx, node.name)
        elif node.kind == _NODE_IF:
            if _truthy(ctx, node.name):
                out += _render_nodes(node.children, ctx)
        elif node.kind == _NODE_FOR:
            if not ctx.lists.__contains__(node.name):
                raise Error(
                    "template: {% for ... in "
                    + node.name
                    + " %} but no list bound to that name"
                )
            var seq = ctx.lists[node.name].copy()
            for k in range(len(seq)):
                # Push the loop variable onto the strings map for
                # the body, then pop after.
                var prior_present = ctx.strings.__contains__(node.loop_var)
                var prior_value = String("")
                if prior_present:
                    prior_value = ctx.strings[node.loop_var].copy()
                ctx.strings[node.loop_var.copy()] = seq[k].copy()
                out += _render_nodes(node.children, ctx)
                if prior_present:
                    ctx.strings[node.loop_var.copy()] = prior_value^
                else:
                    _ = ctx.strings.pop(node.loop_var)
        else:
            raise Error("template: unknown node kind " + String(node.kind))
    return out^


def _lookup_string(ctx: TemplateContext, name: String) raises -> String:
    if ctx.strings.__contains__(name):
        return ctx.strings[name].copy()
    raise Error("template: variable '" + name + "' not bound in context")


def _truthy(ctx: TemplateContext, name: String) raises -> Bool:
    """Truthiness rule: a string is truthy iff non-empty; a
    list is truthy iff len > 0; an unbound name is False."""
    if ctx.strings.__contains__(name):
        return ctx.strings[name].byte_length() > 0
    if ctx.lists.__contains__(name):
        return len(ctx.lists[name]) > 0
    return False


# ── Template ───────────────────────────────────────────────────────────────


@fieldwise_init
struct Template(Copyable, Movable):
    """Compiled template ready to render against a
    :class:`TemplateContext`.

    Use :func:`Template.compile` to parse source bytes once;
    re-render on every request via :func:`Template.render`. The
    compile step is O(N) in source length; the render step is
    O(M) in output length (one pass over the parsed tree, one
    HTML-escape pass per ``{{ var }}``).
    """

    var nodes: List[TemplateNode]

    @staticmethod
    def compile(src: String) raises -> Template:
        """Parse ``src`` into a render-ready :class:`Template`.

        Raises :class:`Error` on:
        - unterminated ``{{...}}`` / ``{%...%}`` tag
        - unmatched ``{% endif %}`` / ``{% endfor %}``
        - empty variable name in ``{{...}}``
        - unsupported filter (only ``| safe`` is accepted)
        - malformed ``{% if %}`` / ``{% for %}`` operand list
        - unknown tag head
        """
        var pos = 0
        var nodes = _parse_segment(src, pos, List[String]())
        return Template(nodes^)

    def render(self, mut ctx: TemplateContext) raises -> String:
        """Walk the parsed tree against ``ctx``, returning the
        rendered output as a ``String``.

        ``ctx`` is taken by mutable borrow because the renderer
        scratches the strings map for ``{% for %}`` loop-variable
        shadowing and restoration. After ``render`` returns,
        ``ctx`` is left exactly as it was before the call.
        """
        return _render_nodes(self.nodes, ctx)
