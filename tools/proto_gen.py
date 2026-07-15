#!/usr/bin/env python3
"""proto3 -> Mojo message codegen for flare.grpc.

Reads a ``.proto`` file (proto3 subset) and emits a Mojo module whose
message structs target the ``flare.grpc.proto`` runtime
(``ProtoWriter`` / ``ProtoReader``). Each generated message gets:

* an explicit no-arg ``__init__`` that fills proto3 defaults,
* ``encode(self) raises -> List[UInt8]`` (proto3 default-skip on the
  wire, unpacked repeated scalars -- valid wire, see ceiling below),
* ``@staticmethod decode(data) raises -> Self`` that accepts BOTH
  packed and unpacked repeated scalars (full read interop) and skips
  unknown fields (proto3 forward compatibility).

Supported proto3 subset: ``message`` (incl. nested), ``enum`` (incl.
nested), scalar fields (double/float/int32/int64/uint32/uint64/
sint32/sint64/bool/string/bytes/fixed32/fixed64), ``repeated`` scalar
and message fields, singular message fields (modeled as
``Optional[Msg]`` for proto3 message presence), and enum fields.

``service`` blocks emit: ``PATH_*`` StaticString consts, a typed
``<Service>Server`` trait, per-RPC byte adapters (bridging the typed
trait onto the runtime GrpcUnary / GrpcServerStreaming /
GrpcClientStreaming / GrpcBidiStreaming traits), a typed
``<Service>Client`` stub wired to ``GrpcClient``, and a serialized
``FileDescriptorProto`` (for reflection). Maps, oneof, groups, and
sfixed* are out of scope.

Note: the encoder writes repeated scalars UNPACKED (one tag per
element) -- valid proto3 wire but larger than protoc's packed default,
costing a few extra tag bytes on big numeric arrays. The decoder reads
both, so interop is intact. A packed LEN block could be emitted later
by exposing a raw-varint sink on ProtoWriter.

Note: type-name resolution is last-component, nearest-scope match,
not full proto name resolution, so two same-named messages in
different packages would collide. Fully-qualified names would need to
be carried through the resolver to fix this.

Usage:
    python3 tools/proto_gen.py INPUT.proto -o OUTPUT.mojo
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field as dc_field


# (mojo_type, wire_const, writer, reader, default_literal, kind)
# kind: "num" | "float" | "bool" | "string" | "bytes"
SCALARS: dict[str, tuple[str, str, str, str, str, str]] = {
    "double": ("Float64", "WIRE_I64", "write_double", "read_double", "0.0", "float"),
    "float": ("Float32", "WIRE_I32", "write_float", "read_float", "0.0", "float"),
    "int32": ("Int64", "WIRE_VARINT", "write_int64", "read_int64", "0", "num"),
    "int64": ("Int64", "WIRE_VARINT", "write_int64", "read_int64", "0", "num"),
    "uint32": ("UInt64", "WIRE_VARINT", "write_uint64", "read_uint64", "0", "num"),
    "uint64": ("UInt64", "WIRE_VARINT", "write_uint64", "read_uint64", "0", "num"),
    "sint32": ("Int64", "WIRE_VARINT", "write_sint64", "read_sint64", "0", "num"),
    "sint64": ("Int64", "WIRE_VARINT", "write_sint64", "read_sint64", "0", "num"),
    "fixed32": ("UInt32", "WIRE_I32", "write_fixed32", "read_fixed32", "0", "num"),
    "fixed64": ("UInt64", "WIRE_I64", "write_fixed64", "read_fixed64", "0", "num"),
    "bool": ("Bool", "WIRE_VARINT", "write_bool", "read_bool", "False", "bool"),
    "string": ("String", "WIRE_LEN", "write_string", "read_string", 'String("")', "string"),
    "bytes": ("List[UInt8]", "WIRE_LEN", "write_bytes", "read_bytes", "List[UInt8]()", "bytes"),
}


@dataclass
class Field:
    name: str
    type_token: str
    number: int
    repeated: bool


@dataclass
class Message:
    name: str  # flattened (Parent_Child)
    fields: list[Field] = dc_field(default_factory=list)


@dataclass
class Enum:
    name: str  # flattened
    values: list[tuple[str, int]] = dc_field(default_factory=list)


@dataclass
class Rpc:
    name: str
    req_type: str
    resp_type: str
    client_streaming: bool
    server_streaming: bool


@dataclass
class Service:
    name: str
    rpcs: list[Rpc] = dc_field(default_factory=list)


class Parser:
    """A small recursive proto3 tokenizer + parser for the supported
    subset. Comments (// and /* */) are stripped first."""

    def __init__(self, text: str):
        text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
        text = re.sub(r"//[^\n]*", " ", text)
        self.toks = re.findall(r"[A-Za-z_][\w.]*|\d+|[{}=;()]", text)
        self.i = 0
        self.messages: list[Message] = []
        self.enums: list[Enum] = []
        self.services: list[Service] = []
        self.package: str = ""

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def next(self) -> str:
        t = self.toks[self.i]
        self.i += 1
        return t

    def expect(self, tok: str) -> None:
        got = self.next()
        if got != tok:
            raise SystemExit(f"proto_gen: expected '{tok}', got '{got}'")

    def parse(self) -> None:
        while self.peek() is not None:
            t = self.next()
            if t == "syntax":
                # syntax = "proto3" ;  (tokens: = proto3 ;) -- the quoted
                # string lost its quotes during tokenization; just drain
                # to the semicolon.
                while self.next() != ";":
                    pass
            elif t == "package":
                self.package = self.next()
                while self.next() != ";":
                    pass
            elif t in ("option", "import"):
                while self.next() != ";":
                    pass
            elif t == "message":
                self._message(prefix="")
            elif t == "enum":
                self._enum(prefix="")
            elif t == "service":
                self._service()
            elif t == ";":
                continue
            else:
                raise SystemExit(f"proto_gen: unexpected top-level token '{t}'")

    def _message(self, prefix: str) -> None:
        name = self.next()
        flat = f"{prefix}{name}"
        self.expect("{")
        msg = Message(name=flat)
        while True:
            t = self.next()
            if t == "}":
                break
            if t == "message":
                self.i -= 1
                self.next()  # re-consume 'message'
                self._message(prefix=f"{flat}_")
                continue
            if t == "enum":
                self._enum(prefix=f"{flat}_")
                continue
            if t == "reserved":
                while self.next() != ";":
                    pass
                continue
            # field:  [repeated] <type> <name> = <number> ;
            repeated = False
            type_token = t
            if t == "repeated":
                repeated = True
                type_token = self.next()
            elif t in ("optional", "required"):
                type_token = self.next()
            fname = self.next()
            self.expect("=")
            number = int(self.next())
            self.expect(";")
            msg.fields.append(Field(fname, type_token, number, repeated))
        self.messages.append(msg)

    def _enum(self, prefix: str) -> None:
        name = self.next()
        flat = f"{prefix}{name}"
        self.expect("{")
        en = Enum(name=flat)
        while True:
            t = self.next()
            if t == "}":
                break
            if t == "option":
                while self.next() != ";":
                    pass
                continue
            vname = t
            self.expect("=")
            vnum = int(self.next())
            self.expect(";")
            en.values.append((vname, vnum))
        self.enums.append(en)

    def _service(self) -> None:
        name = self.next()
        self.expect("{")
        svc = Service(name=name)
        while True:
            t = self.next()
            if t == "}":
                break
            if t == "option":
                while self.next() != ";":
                    pass
                continue
            if t != "rpc":
                raise SystemExit(f"proto_gen: unexpected service token '{t}'")
            # rpc <Method> ( [stream] <Req> ) returns ( [stream] <Resp> ) ;
            mname = self.next()
            self.expect("(")
            client_streaming = False
            req = self.next()
            if req == "stream":
                client_streaming = True
                req = self.next()
            self.expect(")")
            self.expect("returns")
            self.expect("(")
            server_streaming = False
            resp = self.next()
            if resp == "stream":
                server_streaming = True
                resp = self.next()
            self.expect(")")
            # optional method body { ... } or trailing ';'
            nx = self.next()
            if nx == "{":
                depth = 1
                while depth > 0:
                    tok = self.next()
                    if tok == "{":
                        depth += 1
                    elif tok == "}":
                        depth -= 1
            elif nx != ";":
                raise SystemExit(f"proto_gen: expected ';' after rpc, got '{nx}'")
            svc.rpcs.append(
                Rpc(mname, req, resp, client_streaming, server_streaming)
            )
        self.services.append(svc)


class Resolver:
    def __init__(self, messages: list[Message], enums: list[Enum]):
        self.msg_names = {m.name for m in messages}
        self.enum_names = {e.name for e in enums}
        # simple-name -> flattened, last definition wins
        self.simple: dict[str, str] = {}
        for m in messages:
            self.simple[m.name.split("_")[-1]] = m.name
            self.simple[m.name] = m.name
        for e in enums:
            self.simple[e.name.split("_")[-1]] = e.name
            self.simple[e.name] = e.name

    def kind(self, token: str) -> str:
        """Return 'scalar', 'message', or 'enum' for a field type."""
        if token in SCALARS:
            return "scalar"
        flat = self._flatten(token)
        if flat in self.msg_names:
            return "message"
        if flat in self.enum_names:
            return "enum"
        raise SystemExit(f"proto_gen: unknown field type '{token}'")

    def flatten(self, token: str) -> str:
        return self._flatten(token)

    def _flatten(self, token: str) -> str:
        cand = token.replace(".", "_")
        if cand in self.msg_names or cand in self.enum_names:
            return cand
        last = token.split(".")[-1]
        if last in self.simple:
            return self.simple[last]
        return cand


def topo_sort(messages: list[Message], res: Resolver) -> list[Message]:
    """Order messages so each appears after every message it references
    (Mojo resolves field-type annotations at compile time)."""
    by_name = {m.name: m for m in messages}
    ordered: list[Message] = []
    placed: set[str] = set()

    def visit(m: Message, stack: set[str]) -> None:
        if m.name in placed:
            return
        for f in m.fields:
            if res.kind(f.type_token) == "message":
                dep = res.flatten(f.type_token)
                if dep in by_name and dep not in placed and dep not in stack:
                    visit(by_name[dep], stack | {m.name})
        placed.add(m.name)
        ordered.append(m)

    for m in messages:
        visit(m, set())
    return ordered


def mojo_field_type(f: Field, res: Resolver) -> str:
    k = res.kind(f.type_token)
    if k == "scalar":
        base = SCALARS[f.type_token][0]
    elif k == "enum":
        base = "Int"
    else:
        base = res.flatten(f.type_token)
    if f.repeated:
        return f"List[{base}]"
    if k == "message":
        return f"Optional[{base}]"
    return base


def default_literal(f: Field, res: Resolver) -> str:
    if f.repeated:
        inner = mojo_field_type(f, res)[5:-1]
        return f"List[{inner}]()"
    k = res.kind(f.type_token)
    if k == "scalar":
        return SCALARS[f.type_token][4]
    if k == "enum":
        return "0"
    return f"Optional[{res.flatten(f.type_token)}]()"


def emit_message(m: Message, res: Resolver) -> str:
    lines: list[str] = []
    lines.append(f"struct {m.name}(Copyable, Movable):")
    lines.append(f'    """Generated proto3 message ``{m.name}``."""')
    lines.append("")
    for f in m.fields:
        lines.append(f"    var {f.name}: {mojo_field_type(f, res)}")
    lines.append("")
    # default ctor
    lines.append("    def __init__(out self):")
    for f in m.fields:
        lines.append(f"        self.{f.name} = {default_literal(f, res)}")
    lines.append("")
    # encode
    lines.append("    def encode(self) raises -> List[UInt8]:")
    lines.append("        var w = ProtoWriter()")
    for f in m.fields:
        lines.extend("        " + ln for ln in emit_encode_field(f, res))
    lines.append("        return w.take()")
    lines.append("")
    # decode
    lines.append("    @staticmethod")
    lines.append("    def decode(data: Span[UInt8, _]) raises -> Self:")
    lines.append("        var out = Self()")
    lines.append("        var r = ProtoReader(data)")
    lines.append("        while r.has_more():")
    lines.append("            var tw = r.read_tag()")
    lines.append("            var field = tw[0]")
    lines.append("            var wire = tw[1]")
    first = True
    for f in m.fields:
        for cond, body in emit_decode_field(f, res):
            kw = "if" if first else "elif"
            first = False
            lines.append(f"            {kw} {cond}:")
            for ln in body:
                lines.append(f"                {ln}")
    kw = "if" if first else "else"
    if first:
        lines.append("            r.skip(wire)")
    else:
        lines.append("            else:")
        lines.append("                r.skip(wire)")
    lines.append("        return out^")
    lines.append("")
    return "\n".join(lines)


def emit_encode_field(f: Field, res: Resolver) -> list[str]:
    k = res.kind(f.type_token)
    n = f.number
    if f.repeated:
        if k == "scalar":
            spec = SCALARS[f.type_token]
            writer = spec[2]
            arg = _writer_arg(f.type_token, "self." + f.name + "[i]")
            return [
                f"for i in range(len(self.{f.name})):",
                f"    w.{writer}({n}, {arg})",
            ]
        if k == "enum":
            return [
                f"for i in range(len(self.{f.name})):",
                f"    w.write_enum({n}, self.{f.name}[i])",
            ]
        # repeated message
        return [
            f"for i in range(len(self.{f.name})):",
            f"    w.write_message({n}, Span[UInt8, _](self.{f.name}[i].encode()))",
        ]
    if k == "scalar":
        spec = SCALARS[f.type_token]
        writer, kind = spec[2], spec[5]
        arg = _writer_arg(f.type_token, "self." + f.name)
        guard = _scalar_guard(f.name, kind)
        return [f"if {guard}:", f"    w.{writer}({n}, {arg})"]
    if k == "enum":
        return [f"if self.{f.name} != 0:", f"    w.write_enum({n}, self.{f.name})"]
    # singular message
    return [
        f"if Bool(self.{f.name}):",
        f"    w.write_message({n}, Span[UInt8, _](self.{f.name}.value().encode()))",
    ]


def _writer_arg(type_token: str, expr: str) -> str:
    if type_token == "bytes":
        return f"Span[UInt8, _]({expr})"
    return expr


def _scalar_guard(name: str, kind: str) -> str:
    if kind == "bool":
        return f"self.{name}"
    if kind == "float":
        return f"self.{name} != 0.0"
    if kind in ("string",):
        return f"self.{name}.byte_length() > 0"
    if kind == "bytes":
        return f"len(self.{name}) > 0"
    return f"self.{name} != 0"


def emit_decode_field(f: Field, res: Resolver) -> list[tuple[str, list[str]]]:
    k = res.kind(f.type_token)
    n = f.number
    out: list[tuple[str, list[str]]] = []
    if f.repeated and k == "scalar":
        spec = SCALARS[f.type_token]
        wire, reader = spec[1], spec[3]
        # packed: a LEN block of concatenated values
        packed_body = [
            "var packed = r.read_bytes()",
            "var sr = ProtoReader(Span[UInt8, _](packed))",
            "while sr.has_more():",
            f"    out.{f.name}.append(sr.{reader}())",
        ]
        out.append((f"field == {n} and wire == WIRE_LEN", packed_body))
        # unpacked: one tagged value (only when the scalar's own wire
        # type is not already LEN, else the packed branch covers it)
        if wire != "WIRE_LEN":
            out.append(
                (
                    f"field == {n} and wire == {wire}",
                    [f"out.{f.name}.append(r.{reader}())"],
                )
            )
        return out
    if f.repeated and k == "enum":
        out.append(
            (
                f"field == {n} and wire == WIRE_LEN",
                [
                    "var packed = r.read_bytes()",
                    "var sr = ProtoReader(Span[UInt8, _](packed))",
                    "while sr.has_more():",
                    f"    out.{f.name}.append(sr.read_enum())",
                ],
            )
        )
        out.append(
            (
                f"field == {n} and wire == WIRE_VARINT",
                [f"out.{f.name}.append(r.read_enum())"],
            )
        )
        return out
    if f.repeated and k == "message":
        sub = res.flatten(f.type_token)
        out.append(
            (
                f"field == {n} and wire == WIRE_LEN",
                [
                    f"out.{f.name}.append({sub}.decode(Span[UInt8, _](r.read_bytes())))"
                ],
            )
        )
        return out
    if k == "scalar":
        spec = SCALARS[f.type_token]
        wire, reader = spec[1], spec[3]
        out.append((f"field == {n} and wire == {wire}", [f"out.{f.name} = r.{reader}()"]))
        return out
    if k == "enum":
        out.append(
            (f"field == {n} and wire == WIRE_VARINT", [f"out.{f.name} = r.read_enum()"])
        )
        return out
    # singular message
    sub = res.flatten(f.type_token)
    out.append(
        (
            f"field == {n} and wire == WIRE_LEN",
            [
                f"out.{f.name} = Optional[{sub}]({sub}.decode(Span[UInt8, _](r.read_bytes())))"
            ],
        )
    )
    return out


def emit_enum(e: Enum) -> str:
    lines = [f"# proto3 enum {e.name}"]
    for vname, vnum in e.values:
        lines.append(f"comptime {e.name}_{vname}: Int = {vnum}")
    return "\n".join(lines)


# ── FileDescriptorProto (descriptor.proto) serialization ───────────────────
# Hand-encoded protobuf (no protoc dependency) so the emitted descriptor is
# deterministic and golden-testable. Reflection serves these bytes verbatim.

# FieldDescriptorProto.Type enum (descriptor.proto).
_FDP_TYPE = {
    "double": 1, "float": 2, "int64": 3, "uint64": 4, "int32": 5,
    "fixed64": 6, "fixed32": 7, "bool": 8, "string": 9, "bytes": 12,
    "uint32": 13, "sfixed32": 15, "sfixed64": 16, "sint32": 17, "sint64": 18,
}


def _pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _pb_tag(field: int, wire: int) -> bytes:
    return _pb_varint((field << 3) | wire)


def _pb_str(field: int, s: str) -> bytes:
    b = s.encode("utf-8")
    return _pb_tag(field, 2) + _pb_varint(len(b)) + b


def _pb_bool(field: int, v: bool) -> bytes:
    return _pb_tag(field, 0) + _pb_varint(1) if v else b""


def _pb_u32(field: int, n: int) -> bytes:
    return _pb_tag(field, 0) + _pb_varint(n)


def _pb_msg(field: int, body: bytes) -> bytes:
    return _pb_tag(field, 2) + _pb_varint(len(body)) + body


def _fqname(package: str, name: str) -> str:
    """Fully-qualified proto name ``.pkg.Name`` (dotted, not flattened)."""
    dotted = name.replace("_", ".")
    return ("." + package + "." + dotted) if package else ("." + dotted)


def _field_descriptor(f: Field, res: Resolver, package: str) -> bytes:
    """One FieldDescriptorProto: name(1), number(3), label(4), type(5),
    type_name(6 for message/enum)."""
    k = res.kind(f.type_token)
    body = _pb_str(1, f.name) + _pb_u32(3, f.number)
    body += _pb_u32(4, 3 if f.repeated else 1)  # LABEL_REPEATED / OPTIONAL
    if k == "scalar":
        body += _pb_u32(5, _FDP_TYPE[f.type_token])
    elif k == "enum":
        body += _pb_u32(5, 14)  # TYPE_ENUM
        body += _pb_str(6, _fqname(package, res.flatten(f.type_token)))
    else:
        body += _pb_u32(5, 11)  # TYPE_MESSAGE
        body += _pb_str(6, _fqname(package, res.flatten(f.type_token)))
    return body


def _message_descriptor(m: Message, res: Resolver, package: str) -> bytes:
    """DescriptorProto: name(1) + field(2)*. Nested types are emitted flat
    at file scope (the Mojo side flattens too), so no nested_type here."""
    body = _pb_str(1, m.name.split("_")[-1])
    for f in m.fields:
        body += _pb_msg(2, _field_descriptor(f, res, package))
    return body


def _method_descriptor(r: Rpc, res: Resolver, package: str) -> bytes:
    """MethodDescriptorProto: name(1), input_type(2), output_type(3),
    client_streaming(5), server_streaming(6)."""
    body = _pb_str(1, r.name)
    body += _pb_str(2, _fqname(package, res.flatten(r.req_type)))
    body += _pb_str(3, _fqname(package, res.flatten(r.resp_type)))
    body += _pb_bool(5, r.client_streaming)
    body += _pb_bool(6, r.server_streaming)
    return body


def _service_descriptor(s: Service, res: Resolver, package: str) -> bytes:
    body = _pb_str(1, s.name)
    for r in s.rpcs:
        body += _pb_msg(2, _method_descriptor(r, res, package))
    return body


def build_file_descriptor(
    filename: str, p: Parser, res: Resolver
) -> bytes:
    """Serialize a FileDescriptorProto: name(1), package(2),
    message_type(4)*, service(6)*, syntax(12)."""
    out = _pb_str(1, filename)
    if p.package:
        out += _pb_str(2, p.package)
    for m in p.messages:
        out += _pb_msg(4, _message_descriptor(m, res, p.package))
    for s in p.services:
        out += _pb_msg(6, _service_descriptor(s, res, p.package))
    out += _pb_str(12, "proto3")
    return out


def _const_stem(filename: str) -> str:
    base = filename.rsplit("/", 1)[-1]
    if base.endswith(".proto"):
        base = base[: -len(".proto")]
    return re.sub(r"[^0-9A-Za-z]", "_", base).upper()


# ── service codegen (PATH consts, server trait + adapters, client stub) ────


def _method_snake(name: str) -> str:
    """CamelCase rpc name -> snake_case Mojo method name."""
    s = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.lower()


def _path_const(svc: str, rpc: str) -> str:
    return f"{svc.upper()}_{rpc.upper()}_PATH"


def emit_service_paths(s: Service, package: str) -> str:
    lines: list[str] = [f"# service {s.name} RPC paths"]
    for r in s.rpcs:
        full = f"/{package}.{s.name}/{r.name}" if package else f"/{s.name}/{r.name}"
        lines.append(
            f'comptime {_path_const(s.name, r.name)}: StaticString = "{full}"'
        )
    return "\n".join(lines)


def emit_server_trait(s: Service, res: Resolver) -> str:
    lines: list[str] = []
    lines.append(f"trait {s.name}Server(Copyable, Movable):")
    lines.append(
        f'    """Typed server surface for the ``{s.name}`` gRPC service."""'
    )
    lines.append("")
    for r in s.rpcs:
        req = res.flatten(r.req_type)
        resp = res.flatten(r.resp_type)
        m = _method_snake(r.name)
        if r.client_streaming and r.server_streaming:
            sig = (
                f"    def {m}(mut self, ctx: GrpcCallContext,"
                f" requests: List[{req}]) raises -> List[{resp}]:"
            )
        elif r.client_streaming:
            sig = (
                f"    def {m}(mut self, ctx: GrpcCallContext,"
                f" requests: List[{req}]) raises -> {resp}:"
            )
        elif r.server_streaming:
            sig = (
                f"    def {m}(mut self, ctx: GrpcCallContext,"
                f" request: {req}) raises -> List[{resp}]:"
            )
        else:
            sig = (
                f"    def {m}(mut self, ctx: GrpcCallContext,"
                f" request: {req}) raises -> {resp}:"
            )
        lines.append(sig)
        lines.append("        ...")
        lines.append("")
    return "\n".join(lines).rstrip()


def _adapter_name(s: Service, r: Rpc) -> str:
    return f"{s.name}_{r.name}_Adapter"


def emit_rpc_adapter(s: Service, r: Rpc, res: Resolver) -> str:
    req = res.flatten(r.req_type)
    resp = res.flatten(r.resp_type)
    m = _method_snake(r.name)
    name = _adapter_name(s, r)
    hb = f"H: Copyable & {s.name}Server & ImplicitlyDestructible"
    lines: list[str] = []
    lines.append("@fieldwise_init")
    if r.client_streaming and r.server_streaming:
        base = "GrpcBidiStreaming"
    elif r.client_streaming:
        base = "GrpcClientStreaming"
    elif r.server_streaming:
        base = "GrpcServerStreaming"
    else:
        base = "GrpcUnary"
    lines.append(f"struct {name}[{hb}]({base}, Copyable, Movable):")
    lines.append(
        f'    """Byte adapter mapping ``{s.name}.{r.name}`` onto the'
        f' runtime {base} trait."""'
    )
    lines.append("    var handler: Self.H")
    lines.append("")
    if r.client_streaming and r.server_streaming:
        lines.append(
            "    def serve_bidi(mut self, ctx: GrpcCallContext,"
            " messages: List[List[UInt8]]) raises -> GrpcServerStreamReply:"
        )
        lines.append(f"        var reqs = List[{req}]()")
        lines.append("        for i in range(len(messages)):")
        lines.append(
            f"            reqs.append({req}.decode(Span[UInt8, _](messages[i])))"
        )
        lines.append("        var outs = self.handler." + m + "(ctx, reqs^)")
        lines.append("        var raw = List[List[UInt8]]()")
        lines.append("        for i in range(len(outs)):")
        lines.append("            raw.append(outs[i].encode())")
        lines.append("        return GrpcServerStreamReply.ok(raw^)")
    elif r.client_streaming:
        lines.append(
            "    def serve_client_streaming(mut self, ctx: GrpcCallContext,"
            " messages: List[List[UInt8]]) raises -> GrpcUnaryReply:"
        )
        lines.append(f"        var reqs = List[{req}]()")
        lines.append("        for i in range(len(messages)):")
        lines.append(
            f"            reqs.append({req}.decode(Span[UInt8, _](messages[i])))"
        )
        lines.append("        var out = self.handler." + m + "(ctx, reqs^)")
        lines.append("        return GrpcUnaryReply.ok(out.encode())")
    elif r.server_streaming:
        lines.append(
            "    def serve_server_streaming(mut self, ctx: GrpcCallContext,"
            " request_bytes: Span[UInt8, _]) raises -> GrpcServerStreamReply:"
        )
        lines.append(f"        var req = {req}.decode(request_bytes)")
        lines.append("        var outs = self.handler." + m + "(ctx, req)")
        lines.append("        var raw = List[List[UInt8]]()")
        lines.append("        for i in range(len(outs)):")
        lines.append("            raw.append(outs[i].encode())")
        lines.append("        return GrpcServerStreamReply.ok(raw^)")
    else:
        lines.append(
            "    def serve_unary(mut self, ctx: GrpcCallContext,"
            " request_bytes: Span[UInt8, _]) raises -> GrpcUnaryReply:"
        )
        lines.append(f"        var req = {req}.decode(request_bytes)")
        lines.append("        var out = self.handler." + m + "(ctx, req)")
        lines.append("        return GrpcUnaryReply.ok(out.encode())")
    return "\n".join(lines)


def emit_client_stub(s: Service, res: Resolver) -> str:
    lines: list[str] = []
    lines.append("@fieldwise_init")
    lines.append(f"struct {s.name}Client(Copyable, Movable):")
    lines.append(
        f'    """Typed client stub for ``{s.name}``; wraps GrpcClient."""'
    )
    lines.append("    var base_url: String")
    lines.append("")
    for r in s.rpcs:
        req = res.flatten(r.req_type)
        resp = res.flatten(r.resp_type)
        m = _method_snake(r.name)
        path = _path_const(s.name, r.name)
        if r.client_streaming:
            lines.append(f"    def {m}(self) raises -> GrpcBidiStream:")
            lines.append("        var c = GrpcClient(self.base_url)")
            lines.append(f"        return c.call_bidi(String({path}))")
        elif r.server_streaming:
            lines.append(
                f"    def {m}(self, request: {req}) raises -> GrpcServerStream:"
            )
            lines.append("        var c = GrpcClient(self.base_url)")
            lines.append(
                f"        return c.call_server_streaming(String({path}),"
                " Span[UInt8, _](request.encode()))"
            )
        else:
            lines.append(f"    def {m}(self, request: {req}) raises -> {resp}:")
            lines.append("        var c = GrpcClient(self.base_url)")
            lines.append(
                f"        var res = c.call(String({path}),"
                " Span[UInt8, _](request.encode()))"
            )
            lines.append(
                f"        return {resp}.decode(Span[UInt8, _](res.message))"
            )
        lines.append("")
    return "\n".join(lines).rstrip()


def emit_descriptor(filename: str, p: Parser, res: Resolver) -> str:
    fd = build_file_descriptor(filename, p, res)
    stem = _const_stem(filename)
    base = filename.rsplit("/", 1)[-1]
    lines: list[str] = []
    lines.append(f'comptime {stem}_PROTO_FILENAME: StaticString = "{base}"')
    lines.append("")
    lines.append(f"def {stem.lower()}_file_descriptor() -> List[UInt8]:")
    lines.append(
        f'    """Serialized FileDescriptorProto for ``{base}`` (reflection)."""'
    )
    # Emit the bytes as one list literal, wrapped 16 per line.
    nums = list(fd)
    lines.append("    var out: List[UInt8] = [")
    for i in range(0, len(nums), 16):
        chunk = ", ".join(str(b) for b in nums[i : i + 16])
        lines.append(f"        {chunk},")
    lines.append("    ]")
    lines.append("    return out^")
    return "\n".join(lines)


def generate(path_in: str, module_doc: str) -> str:
    with open(path_in, "r") as fh:
        text = fh.read()
    p = Parser(text)
    p.parse()
    res = Resolver(p.messages, p.enums)
    ordered = topo_sort(p.messages, res)

    out: list[str] = []
    out.append(f'"""{module_doc}\n\nGenerated by tools/proto_gen.py from {path_in}.')
    out.append("Do not edit by hand; regenerate from the .proto source.")
    out.append('"""')
    out.append("")
    out.append("from std.collections import List, Optional")
    out.append("from std.memory import Span")
    out.append("")
    out.append(
        "from flare.grpc.proto import (\n"
        "    ProtoReader,\n"
        "    ProtoWriter,\n"
        "    WIRE_I32,\n"
        "    WIRE_I64,\n"
        "    WIRE_LEN,\n"
        "    WIRE_VARINT,\n"
        ")"
    )
    if p.services:
        # Service codegen pulls in the runtime gRPC adapters + client.
        out.append(
            "from flare.grpc import (\n"
            "    GrpcBidiStream,\n"
            "    GrpcBidiStreaming,\n"
            "    GrpcCallContext,\n"
            "    GrpcClient,\n"
            "    GrpcClientStreaming,\n"
            "    GrpcServerStream,\n"
            "    GrpcServerStreamReply,\n"
            "    GrpcServerStreaming,\n"
            "    GrpcUnary,\n"
            "    GrpcUnaryReply,\n"
            ")"
        )
    out.append("")
    out.append("")
    for e in p.enums:
        out.append(emit_enum(e))
        out.append("")
        out.append("")
    for m in ordered:
        out.append(emit_message(m, res))
        out.append("")
    if p.services:
        filename = path_in.rsplit("/", 1)[-1]
        out.append(emit_descriptor(filename, p, res))
        out.append("")
        out.append("")
        for s in p.services:
            out.append(emit_service_paths(s, p.package))
            out.append("")
            out.append("")
            out.append(emit_server_trait(s, res))
            out.append("")
            out.append("")
            for r in s.rpcs:
                out.append(emit_rpc_adapter(s, r, res))
                out.append("")
                out.append("")
            out.append(emit_client_stub(s, res))
            out.append("")
    return "\n".join(out).rstrip() + "\n"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="proto3 -> Mojo codegen")
    ap.add_argument("input", help="input .proto file")
    ap.add_argument("-o", "--output", required=True, help="output .mojo file")
    ap.add_argument(
        "--doc",
        default="Generated proto3 message structs.",
        help="module docstring summary",
    )
    args = ap.parse_args(argv)
    code = generate(args.input, args.doc)
    with open(args.output, "w") as fh:
        fh.write(code)
    print(f"proto_gen: wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
