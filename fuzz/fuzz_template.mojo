"""Fuzz harness: HTML template engine (compile + render).

Compiles arbitrary bytes as template source and, on success, renders
against a small context. Malformed templates must raise ``TemplateError``
(an expected rejection); the compiler + renderer must never panic or read
out of bounds on adversarial ``{{ ... }}`` / ``{% ... %}`` framing.

Run:
    pixi run fuzz-template
"""

from mozz import fuzz, FuzzConfig

from flare.http.template import Template, TemplateContext


def target(data: List[UInt8]) raises:
    """Compile ``data`` as a template, then render it."""
    var s = String(capacity=len(data) + 1)
    for i in range(len(data)):
        s += chr(Int(data[i]))
    try:
        var t = Template.compile(s)
        var ctx = TemplateContext()
        ctx.set("name", "world")
        ctx.set("title", "<b>hi</b>")
        ctx.set("n", "3")
        _ = t.render(ctx)
    except:
        pass  # TemplateError is an expected rejection


def main() raises:
    print("[mozz] fuzzing Template.compile()/render()...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes("Hello {{ name }}!"))
    seeds.append(_bytes("{{ title }}"))
    seeds.append(_bytes("{% if n %}yes{% endif %}"))
    seeds.append(_bytes("{% for x in items %}{{ x }}{% endfor %}"))
    seeds.append(_bytes("{% block a %}default{% endblock %}"))
    seeds.append(_bytes("{{ unterminated"))
    seeds.append(_bytes("{% %}"))
    seeds.append(_bytes("{{}}"))
    seeds.append(_bytes(""))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/template",
            corpus_dir="fuzz/corpus/template",
            max_input_len=1024,
        ),
        seeds,
    )
