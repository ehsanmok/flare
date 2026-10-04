# PLATFORM: any
"""APP-20: negotiate_encoding mishandles the `*` wildcard in Accept-Encoding.

Lean: Flare.Bugs.APP_20.negotiate_violates_spec,
Flare.Bugs.APP_20.negotiate_order_dependent (counterexamples) and
Flare.Bugs.APP_20.fixed_meets_spec (fix meets spec).
flare/http/middleware.mojo:236-240 @59bda50.

RFC 9110 section 12.5.3: "*" matches any available content coding not
explicitly listed, and the acceptable coding with the highest non-zero
qvalue is preferred; "identity;q=0" makes the unencoded form unacceptable.

Expected (brotli available):
  "gzip;q=0.5, *"   -> br   (br gets q=1 through "*")
  "*, gzip;q=0.5"   -> br   (same entries, other order)
Expected (no brotli):
  "identity;q=0, *" -> gzip (identity refused, gzip acceptable via "*")
Actual: gzip, identity, identity. A "*" entry only counts when no
earlier entry set best_q > 0, and it always selects identity.

Minimal fix: record the "*" weight separately (max over "*" entries) and
the per-coding maxima for br / gzip / identity; after the loop give every
coding without an explicit entry the "*" weight, then pick the highest
non-zero weight with ties br > gzip > identity (passthrough when all 0).
"""

from flare.http import negotiate_encoding


def main() raises:
    var a = negotiate_encoding("gzip;q=0.5, *", True)
    var b = negotiate_encoding("*, gzip;q=0.5", True)
    var c = negotiate_encoding("identity;q=0, *", False)
    if a.encoding != "br" or b.encoding != "br" or c.encoding != "gzip":
        print(
            "BUG REPRODUCED: 'gzip;q=0.5, *' ->",
            a.encoding,
            "/ '*, gzip;q=0.5' ->",
            b.encoding,
            "(brotli on, expected br for both); 'identity;q=0, *' ->",
            c.encoding,
            "(expected gzip)",
        )
        raise Error("APP-20")
    print("OK: wildcard weights honoured:", a.encoding, b.encoding, c.encoding)
