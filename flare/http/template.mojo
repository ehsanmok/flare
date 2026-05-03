"""Tiny tag-based template engine.

Askama-shape minimal subset. Supports the three tags that
cover ~90% of HTML / email / config templating use:

* ``{{ name }}`` — variable substitution (HTML-escaped by
  default; ``{{ name | safe }}`` opts out).
* ``{% if name %}...{% endif %}`` — boolean conditional;
  ``name`` is truthy iff non-empty (matches Jinja2 semantics
  for ``string`` truthiness which is the most-common-by-far
  use).
* ``{% for x in name %}...{% endfor %}`` — loop over a
  list-typed context value; each iteration shadows ``x`` for
  the body.

Out of scope (potential future additions):

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
- A future block-inheritance upgrade would be a tree-rewrite,
  not a re-parse.

Performance:

The tree walk is O(N) in the size of the rendered output plus
the number of variable lookups. Variable lookups are O(1)
``Dict`` hits. HTML escape is a single-pass byte loop allocating
one growing buffer. There is no pre-rendered "compiled function"
shape (askama / sailfish do this with codegen at compile time);
flare's reactor latency budget is dominated by network IO not
template render, so the engine keeps the parser-tree-walker
simple.

Error handling:

Both :func:`Template.compile` and :func:`Template.render`
raise the typed :class:`TemplateError` (enumerated; one
``_variant`` field, comptime aliases per condition). Callers
can pattern-match on the variant to distinguish a parse error
from a runtime-rendering error from an unbound-name error,
without ``String(e)`` parsing.

```mojo
from flare.http.template import Template, TemplateContext, TemplateError

try:
    var t = Template.compile("{{ name }")
except e:
    if e == TemplateError.UNTERMINATED_VAR:
        print("forgot to close {{:", e.detail)
```
"""

from std.format import Writable, Writer

from .request import Request


# ── TemplateError ──────────────────────────────────────────────────────────


@fieldwise_init
struct TemplateError(
    Copyable, Equatable, ImplicitlyCopyable, Movable, Writable
):
    """Typed error raised by :func:`Template.compile` /
    :func:`Template.render`.

    Enumerated (``_variant`` Int field) with ``comptime``
    aliases per condition. Equatable so callers can pattern-
    match with ``e == TemplateError.UNTERMINATED_VAR`` etc. The
    ``detail`` field carries human-readable extra context (the
    offending tag name, the unbound variable name, the malformed
    raw text, ...) — empty when the variant is self-explanatory.

    Variants:

    - ``UNTERMINATED_VAR`` — ``{{ ... }}`` opener without a
      matching ``}}`` close.
    - ``UNTERMINATED_TAG`` — ``{% ... %}`` opener without a
      matching ``%}`` close (or a ``{% endtag %}`` whose ``%}``
      ran off the end of source).
    - ``UNKNOWN_FILTER`` — unsupported filter after ``|`` in
      ``{{ name | filter }}``. Only ``| safe`` is accepted.
    - ``EMPTY_VAR`` — ``{{ }}`` or ``{{ | safe }}`` with no
      variable name.
    - ``EMPTY_TAG`` — ``{% %}`` with no tokens.
    - ``MALFORMED_IF`` — ``{% if %}`` not exactly one operand
      after ``if``.
    - ``MALFORMED_FOR`` — ``{% for X in Y %}`` shape violated.
      ``detail`` carries the raw token list.
    - ``UNMATCHED_END`` — ``{% endif %}`` / ``{% endfor %}``
      seen at the top level (no matching opener). ``detail``
      carries the unmatched tag head.
    - ``UNKNOWN_TAG`` — unrecognised control tag in ``{% ... %}``.
      ``detail`` carries the tag head.
    - ``UNBOUND_VARIABLE`` — ``{{ name }}`` for a name not in
      ``ctx.strings``. ``detail`` carries the variable name.
    - ``UNBOUND_ITERABLE`` — ``{% for x in name %}`` for a name
      not in ``ctx.lists``. ``detail`` carries the variable name.
    - ``UNKNOWN_NODE`` — internal: parsed tree contained a node
      kind the renderer doesn't handle. Should be unreachable
      unless ``TemplateNode.kind`` was constructed by hand.
    """

    var _variant: Int
    var detail: String

    comptime UNTERMINATED_VAR = TemplateError(_variant=1, detail=String(""))
    comptime UNTERMINATED_TAG = TemplateError(_variant=2, detail=String(""))
    comptime UNKNOWN_FILTER = TemplateError(_variant=3, detail=String(""))
    comptime EMPTY_VAR = TemplateError(_variant=4, detail=String(""))
    comptime EMPTY_TAG = TemplateError(_variant=5, detail=String(""))
    comptime MALFORMED_IF = TemplateError(_variant=6, detail=String(""))
    comptime MALFORMED_FOR = TemplateError(_variant=7, detail=String(""))
    comptime UNMATCHED_END = TemplateError(_variant=8, detail=String(""))
    comptime UNKNOWN_TAG = TemplateError(_variant=9, detail=String(""))
    comptime UNBOUND_VARIABLE = TemplateError(_variant=10, detail=String(""))
    comptime UNBOUND_ITERABLE = TemplateError(_variant=11, detail=String(""))
    comptime UNKNOWN_NODE = TemplateError(_variant=12, detail=String(""))

    def __eq__(self, other: TemplateError) -> Bool:
        """Compare on the ``_variant`` tag only — ``detail`` is
        human-readable context, not part of the identity."""
        return self._variant == other._variant

    def __ne__(self, other: TemplateError) -> Bool:
        return self._variant != other._variant

    def variant_name(self) -> String:
        if self._variant == 1:
            return String("UNTERMINATED_VAR")
        elif self._variant == 2:
            return String("UNTERMINATED_TAG")
        elif self._variant == 3:
            return String("UNKNOWN_FILTER")
        elif self._variant == 4:
            return String("EMPTY_VAR")
        elif self._variant == 5:
            return String("EMPTY_TAG")
        elif self._variant == 6:
            return String("MALFORMED_IF")
        elif self._variant == 7:
            return String("MALFORMED_FOR")
        elif self._variant == 8:
            return String("UNMATCHED_END")
        elif self._variant == 9:
            return String("UNKNOWN_TAG")
        elif self._variant == 10:
            return String("UNBOUND_VARIABLE")
        elif self._variant == 11:
            return String("UNBOUND_ITERABLE")
        elif self._variant == 12:
            return String("UNKNOWN_NODE")
        return String("UNKNOWN")

    def write_to[W: Writer](self, mut writer: W):
        writer.write("TemplateError(", self.variant_name(), ")")
        if self.detail.byte_length() > 0:
            writer.write(": ", self.detail)


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


# ── Internal: typed-error wrappers around Dict access ──────────────────────
#
# ``Dict[String, T].__getitem__`` raises ``DictKeyError[String]`` (typed).
# Inside a function declared ``raises TemplateError``, calling that
# directly fails to compile per the Mojo doc § "Don't mix error
# types in a single try block". Every Dict access goes through one
# of these two wrappers, both of which absorb the DictKeyError and
# either return the value (if the key was checked first via
# ``__contains__``) or convert to a TemplateError.UNKNOWN_NODE
# internal error.


def _dict_get_string(
    d: Dict[String, String], name: String
) raises TemplateError -> String:
    """Look up a string from ``d`` after a ``__contains__`` check.
    The contains-check guarantees the access succeeds; the
    try/except absorbs Mojo's typed ``DictKeyError`` to keep
    callers' typed-error signature monomorphic."""
    try:
        return d[name].copy()
    except _e:
        raise TemplateError(
            _variant=12,
            detail=String("internal: dict-string lookup of ") + name,
        )


def _dict_get_list(
    d: Dict[String, List[String]], name: String
) raises TemplateError -> List[String]:
    try:
        return d[name].copy()
    except _e:
        raise TemplateError(
            _variant=12,
            detail=String("internal: dict-list lookup of ") + name,
        )


def _dict_set_string(mut d: Dict[String, String], name: String, value: String):
    """``Dict[String, String].__setitem__`` is non-raising on the
    pinned Mojo nightly; this helper exists for symmetry with
    ``_dict_get_string`` so renderer call sites read uniformly."""
    d[name.copy()] = value.copy()


def _dict_pop_string(
    mut d: Dict[String, String], name: String
) raises TemplateError:
    """``Dict.pop`` raises ``DictKeyError`` on miss; the renderer
    only calls this after the corresponding ``__setitem__`` so a
    miss would be an internal bug."""
    try:
        _ = d.pop(name)
    except _e:
        raise TemplateError(
            _variant=12,
            detail=String("internal: dict-string pop of ") + name,
        )


# ── Parser ─────────────────────────────────────────────────────────────────


def _parse_segment(
    src: String, mut pos: Int, until_tags: List[String]
) raises TemplateError -> List[TemplateNode]:
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
        var second = Int(p[open_pos + 1])
        if second == ord("{"):
            var close = _find_close(src, open_pos + 2, "}}")
            if close < 0:
                raise TemplateError(
                    _variant=1,
                    detail=String("opened at byte ") + String(open_pos),
                )
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
                    raise TemplateError(_variant=3, detail=filt^)
                safe = True
                name_part = _strip(_slice(trimmed, 0, pipe_off))
            if name_part.byte_length() == 0:
                raise TemplateError(
                    _variant=4,
                    detail=String("at byte ") + String(open_pos),
                )
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
            var close = _find_close(src, open_pos + 2, "%}")
            if close < 0:
                raise TemplateError(
                    _variant=2,
                    detail=String("opened at byte ") + String(open_pos),
                )
            var raw = _strip(_slice(src, open_pos + 2, close))
            pos = close + 2
            var tokens = _split_ws(raw)
            if len(tokens) == 0:
                raise TemplateError(
                    _variant=5,
                    detail=String("at byte ") + String(open_pos),
                )
            var head = tokens[0]
            if _matches(until_tags, head):
                pos = open_pos
                return out^
            if head == String("if"):
                if len(tokens) != 2:
                    raise TemplateError(
                        _variant=6,
                        detail=String("expected one operand, got ")
                        + String(len(tokens) - 1),
                    )
                var children = _parse_segment(src, pos, _list("endif"))
                pos = _skip_tag(src, pos)
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
                    raise TemplateError(_variant=7, detail=raw^)
                var loop_v = tokens[1].copy()
                var iter_n = tokens[3].copy()
                var children = _parse_segment(src, pos, _list("endfor"))
                pos = _skip_tag(src, pos)
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
                raise TemplateError(_variant=8, detail=head.copy())
            else:
                raise TemplateError(_variant=9, detail=head.copy())
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


def _skip_tag(src: String, pos: Int) raises TemplateError -> Int:
    """Given ``pos`` pointing at the start of a ``{% TAG %}``
    end tag (validated by ``_parse_segment``), return the byte
    position immediately after ``%}``."""
    var close = _find_close(src, pos + 2, "%}")
    if close < 0:
        raise TemplateError(
            _variant=2,
            detail=String("end-tag opened at byte ") + String(pos),
        )
    return close + 2


# ── Renderer ───────────────────────────────────────────────────────────────


def _render_nodes(
    nodes: List[TemplateNode], mut ctx: TemplateContext
) raises TemplateError -> String:
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
                raise TemplateError(_variant=11, detail=node.name.copy())
            var seq = _dict_get_list(ctx.lists, node.name)
            for k in range(len(seq)):
                var prior_present = ctx.strings.__contains__(node.loop_var)
                var prior_value = String("")
                if prior_present:
                    prior_value = _dict_get_string(ctx.strings, node.loop_var)
                _dict_set_string(ctx.strings, node.loop_var, seq[k])
                out += _render_nodes(node.children, ctx)
                if prior_present:
                    _dict_set_string(ctx.strings, node.loop_var, prior_value)
                else:
                    _dict_pop_string(ctx.strings, node.loop_var)
        else:
            raise TemplateError(
                _variant=12,
                detail=String("kind=") + String(node.kind),
            )
    return out^


def _lookup_string(
    ctx: TemplateContext, name: String
) raises TemplateError -> String:
    if ctx.strings.__contains__(name):
        return _dict_get_string(ctx.strings, name)
    raise TemplateError(_variant=10, detail=name.copy())


def _truthy(ctx: TemplateContext, name: String) raises TemplateError -> Bool:
    """Truthiness rule: a string is truthy iff non-empty; a
    list is truthy iff len > 0; an unbound name is False."""
    if ctx.strings.__contains__(name):
        return _dict_get_string(ctx.strings, name).byte_length() > 0
    if ctx.lists.__contains__(name):
        return len(_dict_get_list(ctx.lists, name)) > 0
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
    def compile(src: String) raises TemplateError -> Template:
        """Parse ``src`` into a render-ready :class:`Template`.

        Raises :class:`TemplateError` (variant indicates which):

        - ``UNTERMINATED_VAR`` — unterminated ``{{...}}``
        - ``UNTERMINATED_TAG`` — unterminated ``{%...%}``
        - ``UNMATCHED_END`` — unmatched ``{% endif %}`` /
          ``{% endfor %}``
        - ``EMPTY_VAR`` — empty variable name in ``{{...}}``
        - ``EMPTY_TAG`` — empty ``{% %}``
        - ``UNKNOWN_FILTER`` — only ``| safe`` is accepted
        - ``MALFORMED_IF`` — wrong operand count
        - ``MALFORMED_FOR`` — ``{% for X in Y %}`` shape violated
        - ``UNKNOWN_TAG`` — unrecognised tag head
        """
        var pos = 0
        var nodes = _parse_segment(src, pos, List[String]())
        return Template(nodes^)

    def render(self, mut ctx: TemplateContext) raises TemplateError -> String:
        """Walk the parsed tree against ``ctx``, returning the
        rendered output as a ``String``.

        ``ctx`` is taken by mutable borrow because the renderer
        scratches the strings map for ``{% for %}`` loop-variable
        shadowing and restoration. After ``render`` returns,
        ``ctx`` is left exactly as it was before the call.

        Raises :class:`TemplateError` (variant indicates which):

        - ``UNBOUND_VARIABLE`` — ``{{ name }}`` for a name not
          in ``ctx.strings``.
        - ``UNBOUND_ITERABLE`` — ``{% for x in name %}`` for a
          name not in ``ctx.lists``.
        - ``UNKNOWN_NODE`` — internal: parsed tree contained a
          node kind the renderer doesn't handle.
        """
        return _render_nodes(self.nodes, ctx)
