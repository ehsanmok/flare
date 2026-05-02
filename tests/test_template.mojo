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
7. Parser raises on: unterminated ``{{``, unterminated ``{%``,
   stray ``{% endif %}``, unknown tag, unknown filter, empty
   variable name, malformed ``{% for %}`` operand list.
8. Renderer raises on: unbound ``{{ var }}``, unbound
   ``{% for %}`` iterable.
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
    var raised = False
    try:
        var _r = t.render(ctx)
    except:
        raised = True
    assert_true(raised)


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
    var raised = False
    try:
        var _r = t.render(ctx)
    except:
        raised = True
    assert_true(raised)


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


# ── parser errors ─────────────────────────────────────────────────────────


def test_unterminated_var_tag_raises() raises:
    var raised = False
    try:
        var _t = Template.compile(String("hello {{ name "))
    except:
        raised = True
    assert_true(raised)


def test_unterminated_control_tag_raises() raises:
    var raised = False
    try:
        var _t = Template.compile(String("hello {% if x "))
    except:
        raised = True
    assert_true(raised)


def test_stray_endif_raises() raises:
    var raised = False
    try:
        var _t = Template.compile(String("hello {% endif %}"))
    except:
        raised = True
    assert_true(raised)


def test_unknown_tag_raises() raises:
    var raised = False
    try:
        var _t = Template.compile(String("hello {% wat %}"))
    except:
        raised = True
    assert_true(raised)


def test_unknown_filter_raises() raises:
    var raised = False
    try:
        var _t = Template.compile(String("{{ name | upper }}"))
    except:
        raised = True
    assert_true(raised)


def test_empty_var_name_raises() raises:
    var raised = False
    try:
        var _t = Template.compile(String("{{ }}"))
    except:
        raised = True
    assert_true(raised)


def test_malformed_for_raises() raises:
    var raised = False
    try:
        var _t = Template.compile(String("{% for x xs %}{% endfor %}"))
    except:
        raised = True
    assert_true(raised)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
