"""Shared I/O for the difftest drivers.

A batch file holds one case per line, ``target<TAB>hex-input``. A driver
answers each case with one line, ``OK:<payload>`` or ``ERR``, in the same
format as the Lean oracle (formal/Oracle/Codec.lean), so the runner can
compare the two outputs as text.
"""


struct Case(Copyable, Movable):
    var target: String
    var data: List[UInt8]

    def __init__(out self, var target: String, var data: List[UInt8]):
        self.target = target^
        self.data = data^


def _nibble(c: UInt8) raises -> Int:
    if c >= 48 and c <= 57:
        return Int(c) - 48
    if c >= 97 and c <= 102:
        return Int(c) - 87
    if c >= 65 and c <= 70:
        return Int(c) - 55
    raise Error("difftest: bad hex digit")


def read_cases(path: String) raises -> List[Case]:
    var text: String
    with open(path, "r") as f:
        text = f.read()
    var b = text.as_bytes()
    var out = List[Case]()
    var i = 0
    var n = len(b)
    while i < n:
        var tab = i
        while tab < n and b[tab] != 9 and b[tab] != 10:
            tab += 1
        if tab >= n or b[tab] != 9:
            i = tab + 1
            continue
        var name = String(unsafe_from_utf8=b[i:tab])
        var j = tab + 1
        var data = List[UInt8]()
        while j + 1 < n and b[j] != 10:
            data.append(UInt8(_nibble(b[j]) * 16 + _nibble(b[j + 1])))
            j += 2
        while j < n and b[j] != 10:
            j += 1
        out.append(Case(name^, data^))
        i = j + 1
    return out^


def hex(data: Span[UInt8, _]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var out = List[UInt8]()
    for x in data:
        out.append(digits[Int(x >> 4)])
        out.append(digits[Int(x & 15)])
    return String(unsafe_from_utf8=Span[UInt8, _](out))


def ok_hex(data: Span[UInt8, _]) -> String:
    return "OK:" + hex(data)


def be_take(n: Int, data: List[UInt8]) -> UInt64:
    var v: UInt64 = 0
    for i in range(min(n, len(data))):
        v = (v << 8) | UInt64(data[i])
    return v


def write_lines(path: String, lines: List[String]) raises:
    var out = String()
    for line in lines:
        out += line
        out += "\n"
    with open(path, "w") as f:
        f.write(out)
