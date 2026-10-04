import Flare.Core

/-!
# Header-name byte constants

String literals from `flare/http2/state.mojo` spelled as explicit byte
lists, so the kernel can compare them by `decide`.
-/
namespace Flare.L3.H2.Names

/-- ":method" -/
def kMethod : Bytes := [58, 109, 101, 116, 104, 111, 100]
/-- ":scheme" -/
def kScheme : Bytes := [58, 115, 99, 104, 101, 109, 101]
/-- ":path" -/
def kPath : Bytes := [58, 112, 97, 116, 104]
/-- ":authority" -/
def kAuthority : Bytes := [58, 97, 117, 116, 104, 111, 114, 105, 116, 121]
/-- ":protocol" -/
def kProtocol : Bytes := [58, 112, 114, 111, 116, 111, 99, 111, 108]
/-- ":status" -/
def kStatus : Bytes := [58, 115, 116, 97, 116, 117, 115]
/-- "host" -/
def kHost : Bytes := [104, 111, 115, 116]
/-- "te" -/
def kTe : Bytes := [116, 101]
/-- "trailers" -/
def kTrailers : Bytes := [116, 114, 97, 105, 108, 101, 114, 115]
/-- "CONNECT" -/
def kConnect : Bytes := [67, 79, 78, 78, 69, 67, 84]
/-- "OPTIONS" -/
def kOptions : Bytes := [79, 80, 84, 73, 79, 78, 83]
/-- "connection" -/
def kConnection : Bytes := [99, 111, 110, 110, 101, 99, 116, 105, 111, 110]
/-- "keep-alive" -/
def kKeepAlive : Bytes := [107, 101, 101, 112, 45, 97, 108, 105, 118, 101]
/-- "proxy-connection" -/
def kProxyConnection : Bytes := [112, 114, 111, 120, 121, 45, 99, 111, 110, 110, 101, 99, 116, 105, 111, 110]
/-- "transfer-encoding" -/
def kTransferEncoding : Bytes := [116, 114, 97, 110, 115, 102, 101, 114, 45, 101, 110, 99, 111, 100, 105, 110, 103]
/-- "upgrade" -/
def kUpgrade : Bytes := [117, 112, 103, 114, 97, 100, 101]
/-- "content-length" -/
def kContentLength : Bytes := [99, 111, 110, 116, 101, 110, 116, 45, 108, 101, 110, 103, 116, 104]

end Flare.L3.H2.Names
