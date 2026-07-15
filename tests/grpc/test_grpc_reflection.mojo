"""Tests for gRPC server reflection (list_services + error path)."""

from std.memory import Span
from std.testing import assert_equal, assert_true, TestSuite

from flare.grpc import GrpcCallContext, GrpcMetadata
from flare.grpc.proto import ProtoReader, ProtoWriter, WIRE_LEN
from flare.grpc.reflection import (
    REFLECT_ERROR_RESPONSE,
    REFLECT_FILE_BY_FILENAME,
    REFLECT_FILE_CONTAINING_SYMBOL,
    REFLECT_FILE_DESCRIPTOR_RESPONSE,
    REFLECT_LIST_SERVICES,
    REFLECT_LIST_SERVICES_RESPONSE,
    ReflectionBidiHandler,
    ReflectionRequest,
    ReflectionService,
)
from flare.grpc.status import GRPC_STATUS_NOT_FOUND, GRPC_STATUS_UNIMPLEMENTED


def _request(field: Int, arg: String) raises -> List[UInt8]:
    var w = ProtoWriter()
    w.write_string(field, arg)
    return w.take()


def _service_names(response: List[UInt8]) raises -> List[String]:
    """Walk a ServerReflectionResponse and pull every service name out
    of the nested ListServiceResponse (field 6)."""
    var names = List[String]()
    var r = ProtoReader(Span[UInt8, _](response))
    while r.has_more():
        var tw = r.read_tag()
        if tw[0] == REFLECT_LIST_SERVICES_RESPONSE and tw[1] == WIRE_LEN:
            var list_bytes = r.read_bytes()
            var lr = ProtoReader(Span[UInt8, _](list_bytes))
            while lr.has_more():
                var ltw = lr.read_tag()
                if ltw[0] == 1 and ltw[1] == WIRE_LEN:
                    var svc_bytes = lr.read_bytes()
                    var sr = ProtoReader(Span[UInt8, _](svc_bytes))
                    while sr.has_more():
                        var stw = sr.read_tag()
                        if stw[0] == 1 and stw[1] == WIRE_LEN:
                            names.append(sr.read_string())
                        else:
                            sr.skip(stw[1])
                else:
                    lr.skip(ltw[1])
        else:
            r.skip(tw[1])
    return names^


def _error_code(response: List[UInt8]) raises -> Int:
    """Return the ErrorResponse.error_code from field 7, or -1."""
    var r = ProtoReader(Span[UInt8, _](response))
    while r.has_more():
        var tw = r.read_tag()
        if tw[0] == REFLECT_ERROR_RESPONSE and tw[1] == WIRE_LEN:
            var err_bytes = r.read_bytes()
            var er = ProtoReader(Span[UInt8, _](err_bytes))
            while er.has_more():
                var etw = er.read_tag()
                if etw[0] == 1:
                    return Int(er.read_int64())
                else:
                    er.skip(etw[1])
        else:
            r.skip(tw[1])
    return -1


def test_request_decode_list_services() raises:
    var bytes = _request(REFLECT_LIST_SERVICES, String("*"))
    var req = ReflectionRequest.decode(Span[UInt8, _](bytes))
    assert_equal(req.kind, REFLECT_LIST_SERVICES)
    assert_equal(req.arg, String("*"))


def test_list_services_response() raises:
    var svc = ReflectionService()
    svc.register(String("flare.sample.Greeter"))
    svc.register(String("grpc.health.v1.Health"))
    var req = _request(REFLECT_LIST_SERVICES, String(""))
    var resp = svc.answer(Span[UInt8, _](req))
    var names = _service_names(resp)
    assert_equal(len(names), 2)
    assert_equal(names[0], String("flare.sample.Greeter"))
    assert_equal(names[1], String("grpc.health.v1.Health"))


def test_unregistered_descriptor_returns_not_found() raises:
    var svc = ReflectionService()
    svc.register(String("flare.sample.Greeter"))
    var req = _request(REFLECT_FILE_BY_FILENAME, String("sample.proto"))
    var resp = svc.answer(Span[UInt8, _](req))
    assert_equal(_error_code(resp), GRPC_STATUS_NOT_FOUND)
    assert_equal(len(_service_names(resp)), 0)


def _descriptor_bytes(response: List[UInt8]) raises -> List[UInt8]:
    """Pull the FileDescriptorResponse.file_descriptor_proto (field 4 ->
    inner field 1) out of a ServerReflectionResponse, or empty."""
    var r = ProtoReader(Span[UInt8, _](response))
    while r.has_more():
        var tw = r.read_tag()
        if tw[0] == REFLECT_FILE_DESCRIPTOR_RESPONSE and tw[1] == WIRE_LEN:
            var fdr = r.read_bytes()
            var fr = ProtoReader(Span[UInt8, _](fdr))
            while fr.has_more():
                var ftw = fr.read_tag()
                if ftw[0] == 1 and ftw[1] == WIRE_LEN:
                    return fr.read_bytes()
                else:
                    fr.skip(ftw[1])
        else:
            r.skip(tw[1])
    return List[UInt8]()


def test_file_by_filename_returns_descriptor() raises:
    var svc = ReflectionService()
    var fdp: List[UInt8] = [1, 2, 3, 4, 5]
    var symbols = List[String]()
    symbols.append(String("flare.sample.Greeter"))
    svc.register_descriptor(String("sample.proto"), fdp^, symbols)
    var req = _request(REFLECT_FILE_BY_FILENAME, String("sample.proto"))
    var resp = svc.answer(Span[UInt8, _](req))
    var got = _descriptor_bytes(resp)
    assert_equal(len(got), 5)
    assert_equal(got[0], UInt8(1))
    assert_equal(got[4], UInt8(5))


def test_file_containing_symbol_returns_descriptor() raises:
    var svc = ReflectionService()
    var fdp: List[UInt8] = [9, 8, 7]
    var symbols = List[String]()
    symbols.append(String("flare.sample.Greeter"))
    svc.register_descriptor(String("sample.proto"), fdp^, symbols)
    var req = _request(
        REFLECT_FILE_CONTAINING_SYMBOL, String("flare.sample.Greeter")
    )
    var resp = svc.answer(Span[UInt8, _](req))
    var got = _descriptor_bytes(resp)
    assert_equal(len(got), 3)
    assert_equal(got[0], UInt8(9))
    # A symbol we did not register misses with NOT_FOUND.
    var miss = _request(REFLECT_FILE_CONTAINING_SYMBOL, String("nope.Nope"))
    var miss_resp = svc.answer(Span[UInt8, _](miss))
    assert_equal(_error_code(miss_resp), GRPC_STATUS_NOT_FOUND)


def test_bidi_handler_answers_each_message() raises:
    var svc = ReflectionService()
    svc.register(String("flare.sample.Greeter"))
    var handler = ReflectionBidiHandler(svc^)
    var msgs = List[List[UInt8]]()
    msgs.append(_request(REFLECT_LIST_SERVICES, String("")))
    msgs.append(_request(REFLECT_LIST_SERVICES, String("")))
    var ctx = GrpcCallContext(
        path=String("/grpc.reflection.v1alpha.ServerReflection/"),
        deadline_us=UInt64(0),
        initial_metadata=GrpcMetadata(),
        accept_encoding=String(""),
    )
    var reply = handler.serve_bidi(ctx, msgs^)
    assert_equal(len(reply.messages), 2)
    assert_equal(len(_service_names(reply.messages[0])), 1)
    assert_equal(len(_service_names(reply.messages[1])), 1)


def main() raises:
    print("=" * 60)
    print("test_grpc_reflection.mojo -- server reflection v1alpha")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
