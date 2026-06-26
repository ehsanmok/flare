"""Tests for gRPC server reflection (list_services + error path)."""

from std.memory import Span
from std.testing import assert_equal, assert_true, TestSuite

from flare.grpc.proto import ProtoReader, ProtoWriter, WIRE_LEN
from flare.grpc.reflection import (
    REFLECT_ERROR_RESPONSE,
    REFLECT_FILE_BY_FILENAME,
    REFLECT_LIST_SERVICES,
    REFLECT_LIST_SERVICES_RESPONSE,
    ReflectionRequest,
    ReflectionService,
)
from flare.grpc.status import GRPC_STATUS_UNIMPLEMENTED


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


def test_descriptor_request_returns_unimplemented() raises:
    var svc = ReflectionService()
    svc.register(String("flare.sample.Greeter"))
    var req = _request(REFLECT_FILE_BY_FILENAME, String("sample.proto"))
    var resp = svc.answer(Span[UInt8, _](req))
    assert_equal(_error_code(resp), GRPC_STATUS_UNIMPLEMENTED)
    # No list_services payload on the error path.
    assert_equal(len(_service_names(resp)), 0)


def main() raises:
    print("=" * 60)
    print("test_grpc_reflection.mojo -- server reflection v1alpha")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
