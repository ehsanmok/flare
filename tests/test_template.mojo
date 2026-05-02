"""Tests for :mod:`flare.http.template`.

Coverage:

1. ``html_escape`` covers the OWASP rule #1+#2 byte set (``&``,
   ``<``, ``>``, ``"``, ``'``).
2. Plain-text template (no tags) round-trips.
3. ``{{ var }}`` substitution + HTML escape; ``{{ var | safe }}``
   skips escape.
4. ``{% if name %}...{% endif %}`` shows / hides body based on
   string-truthiness (non-empty = true, empty = false, unbound
   = false), and on list-truthiness (non-empty = true).
5. ``{% for x in xs %}...{% endfor %}`` iterates and shadows
   ``x`` for the body; outer ``x`` (if any) is restored.
6. Nested ``{% if %}`` inside ``{% for %}`` and vice-versa.
7. Parser raises typed :class:`TemplateError` with the right
   variant on: unterminated ``{{``, unterminated ``{%``,
   stray ``{% endif %}``, unknown tag, unknown filter, empty
   variable name, malformed ``{% for %}`` operand list.
8. Renderer raises typed :class:`TemplateError` with the right
   variant on: unbound ``{{ var }}``, unbound ``{% for %}``
   iterable.
9. ``TemplateError`` rendering, equality, and field access.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from flare.http.template import (
    Template,
    TemplateContext,
    TemplateError,
    html_escape,
)


# ── html_escape ───────────────────────────────────────────────────────────


def test_html_escape_passes_safe_text() raises:
    assert_equal(html_escape(String("hello world")), String("hello world"))


def test_html_escape_handles_all_five_bytes() raises:
    assert_equal(
        html_escape(String('<a href="x?y=1&z=2">\'</a>')),
        String("&lt;a href=&quot;x?y=1&amp;z=2&quot;&gt;&#x27;&lt;/a&gt;"),
    )


def test_html_escape_empty_string_round_trips() raises:
    assert_equal(html_escape(String("")), String(""))


# ── Plain text ─────────────────────────────────────────────────────────────


def test_plain_text_unchanged() raises:
    var t = Template.compile(String("hello world"))
    var ctx = TemplateContext()
    assert_equal(t.render(ctx), String("hello world"))


def test_empty_template_renders_empty() raises:
    var t = Template.compile(String(""))
    var ctx = TemplateContext()
    assert_equal(t.render(ctx), String(""))


# ── {{ var }} ──────────────────────────────────────────────────────────────


def test_var_substitution() raises:
    var t = Template.compile(String("Hello {{ name }}!"))
    var ctx = TemplateContext()
    ctx.set(String("name"), String("Alice"))
    assert_equal(t.render(ctx), String("Hello Alice!"))


def test_var_substitution_html_escapes_by_default() raises:
    var t = Template.compile(String("<p>{{ user }}</p>"))
    var ctx = TemplateContext()
    ctx.set(String("user"), String("<script>alert(1)</script>"))
    assert_equal(
        t.render(ctx),
        String("<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"),
    )


def test_var_safe_filter_skips_escape() raises:
    var t = Template.compile(String("<p>{{ html | safe }}</p>"))
    var ctx = TemplateContext()
    ctx.set(String("html"), String("<b>bold</b>"))
    assert_equal(t.render(ctx), String("<p><b>bold</b></p>"))


def test_var_unbound_raises() raises:
    var t = Template.compile(String("{{ missing }}"))
    var ctx = TemplateContext()
    var got_variant = 0
    var got_detail = String("")
    try:
        var _r = t.render(ctx)
    except e:
        got_variant = e._variant
        got_detail = e.detail.copy()
    assert_true(got_variant == TemplateError.UNBOUND_VARIABLE._variant)
    assert_equal(got_detail, String("missing"))


# ── {% if %} ──────────────────────────────────────────────────────────────


def test_if_truthy_string_renders_body() raises:
    var t = Template.compile(String("{% if name %}hi {{ name }}{% endif %}"))
    var ctx = TemplateContext()
    ctx.set(String("name"), String("Alice"))
    assert_equal(t.render(ctx), String("hi Alice"))


def test_if_empty_string_skips_body() raises:
    var t = Template.compile(String("{% if name %}hi{% endif %}done"))
    var ctx = TemplateContext()
    ctx.set(String("name"), String(""))
    assert_equal(t.render(ctx), String("done"))


def test_if_unbound_skips_body() raises:
    var t = Template.compile(String("[{% if x %}yes{% endif %}]"))
    var ctx = TemplateContext()
    assert_equal(t.render(ctx), String("[]"))


def test_if_truthy_list_renders_body() raises:
    var t = Template.compile(String("{% if xs %}some{% endif %}"))
    var ctx = TemplateContext()
    var xs = List[String]()
    xs.append(String("a"))
    ctx.set_list(String("xs"), xs)
    assert_equal(t.render(ctx), String("some"))


# ── {% for %} ─────────────────────────────────────────────────────────────


def test_for_iterates_over_list() raises:
    var t = Template.compile(String("[{% for x in xs %}{{ x }};{% endfor %}]"))
    var ctx = TemplateContext()
    var xs = List[String]()
    xs.append(String("a"))
    xs.append(String("b"))
    xs.append(String("c"))
    ctx.set_list(String("xs"), xs)
    assert_equal(t.render(ctx), String("[a;b;c;]"))


def test_for_loop_var_shadowing_restores_outer_value() raises:
    var t = Template.compile(
        String("{{ x }} | {% for x in xs %}{{ x }}.{% endfor %} | {{ x }}")
    )
    var ctx = TemplateContext()
    ctx.set(String("x"), String("OUTER"))
    var xs = List[String]()
    xs.append(String("a"))
    xs.append(String("b"))
    ctx.set_list(String("xs"), xs)
    assert_equal(t.render(ctx), String("OUTER | a.b. | OUTER"))


def test_for_loop_var_unbinds_after_loop_when_no_prior() raises:
    """If ``x`` was not bound before the loop, it must not leak
    out as a bound name afterwards."""
    var t = Template.compile(
        String("{% for x in xs %}{{ x }};{% endfor %}{% if x %}LEAK{% endif %}")
    )
    var ctx = TemplateContext()
    var xs = List[String]()
    xs.append(String("a"))
    ctx.set_list(String("xs"), xs)
    assert_equal(t.render(ctx), String("a;"))


def test_for_unbound_iterable_raises() raises:
    var t = Template.compile(String("{% for x in xs %}{{ x }}{% endfor %}"))
    var ctx = TemplateContext()
    var got_variant = 0
    var got_detail = String("")
    try:
        var _r = t.render(ctx)
    except e:
        got_variant = e._variant
        got_detail = e.detail.copy()
    assert_true(got_variant == TemplateError.UNBOUND_ITERABLE._variant)
    assert_equal(got_detail, String("xs"))


# ── nesting ───────────────────────────────────────────────────────────────


def test_for_inside_if() raises:
    var t = Template.compile(
        String("{% if xs %}[{% for x in xs %}{{ x }},{% endfor %}]{% endif %}")
    )
    var ctx = TemplateContext()
    var xs = List[String]()
    xs.append(String("alpha"))
    xs.append(String("beta"))
    ctx.set_list(String("xs"), xs)
    assert_equal(t.render(ctx), String("[alpha,beta,]"))


def test_if_inside_for() raises:
    var t = Template.compile(
        String("{% for x in xs %}{% if show %}({{ x }}){% endif %}{% endfor %}")
    )
    var ctx = TemplateContext()
    ctx.set(String("show"), String("yes"))
    var xs = List[String]()
    xs.append(String("a"))
    xs.append(String("b"))
    ctx.set_list(String("xs"), xs)
    assert_equal(t.render(ctx), String("(a)(b)"))


# ── parser errors (typed-error variant + detail) ──────────────────────────


def test_unterminated_var_tag_raises_unterminated_var() raises:
    var got_variant = 0
    try:
        var _t = Template.compile(String("hello {{ name "))
    except e:
        got_variant = e._variant
    assert_true(got_variant == TemplateError.UNTERMINATED_VAR._variant)


def test_unterminated_control_tag_raises_unterminated_tag() raises:
    var got_variant = 0
    try:
        var _t = Template.compile(String("hello {% if x "))
    except e:
        got_variant = e._variant
    assert_true(got_variant == TemplateError.UNTERMINATED_TAG._variant)


def test_stray_endif_raises_unmatched_end() raises:
    var got_variant = 0
    var got_detail = String("")
    try:
        var _t = Template.compile(String("hello {% endif %}"))
    except e:
        got_variant = e._variant
        got_detail = e.detail.copy()
    assert_true(got_variant == TemplateError.UNMATCHED_END._variant)
    assert_equal(got_detail, String("endif"))


def test_unknown_tag_raises_unknown_tag() raises:
    var got_variant = 0
    var got_detail = String("")
    try:
        var _t = Template.compile(String("hello {% wat %}"))
    except e:
        got_variant = e._variant
        got_detail = e.detail.copy()
    assert_true(got_variant == TemplateError.UNKNOWN_TAG._variant)
    assert_equal(got_detail, String("wat"))


def test_unknown_filter_raises_unknown_filter() raises:
    var got_variant = 0
    var got_detail = String("")
    try:
        var _t = Template.compile(String("{{ name | upper }}"))
    except e:
        got_variant = e._variant
        got_detail = e.detail.copy()
    assert_true(got_variant == TemplateError.UNKNOWN_FILTER._variant)
    assert_equal(got_detail, String("upper"))


def test_empty_var_name_raises_empty_var() raises:
    var got_variant = 0
    try:
        var _t = Template.compile(String("{{ }}"))
    except e:
        got_variant = e._variant
    assert_true(got_variant == TemplateError.EMPTY_VAR._variant)


def test_malformed_for_raises_malformed_for() raises:
    var got_variant = 0
    try:
        var _t = Template.compile(String("{% for x xs %}{% endfor %}"))
    except e:
        got_variant = e._variant
    assert_true(got_variant == TemplateError.MALFORMED_FOR._variant)


# ── TemplateError shape ────────────────────────────────────────────────────


def test_template_error_eq_compares_on_variant_only() raises:
    var a = TemplateError(_variant=10, detail=String("name1"))
    var b = TemplateError(_variant=10, detail=String("name2"))
    var c = TemplateError(_variant=11, detail=String("name1"))
    assert_true(a == b)
    assert_true(a != c)
    assert_true(b != c)


def test_template_error_write_to_renders_variant_and_detail() raises:
    var e = TemplateError(_variant=10, detail=String("name"))
    assert_equal(String(e), String("TemplateError(UNBOUND_VARIABLE): name"))


def test_template_error_write_to_omits_empty_detail() raises:
    var e = TemplateError(_variant=4, detail=String(""))
    assert_equal(String(e), String("TemplateError(EMPTY_VAR)"))


def test_template_error_constants_have_distinct_variants() raises:
    assert_true(
        TemplateError.UNTERMINATED_VAR._variant
        != TemplateError.UNTERMINATED_TAG._variant
    )
    assert_true(
        TemplateError.UNBOUND_VARIABLE._variant
        != TemplateError.UNBOUND_ITERABLE._variant
    )
    assert_true(
        TemplateError.UNKNOWN_TAG._variant
        != TemplateError.UNKNOWN_FILTER._variant
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
