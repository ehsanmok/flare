"""HTTP redirect policy: configurable cross-origin + auth gating.

The v0.6 ``HttpClient`` follows redirects unconditionally up to a
configurable hop count and silently strips state-changing methods
(POST → GET on 301/302/303, per the spec). That covers the
80% case but leaves three sharp edges for callers who care:

1. **Cross-origin redirects.** A 302 from ``api.example.com`` to
   ``evil.com`` is a textbook open-redirect leak — every
   request your client sends to ``api.example.com`` (including
   the Authorization header, cookies, custom auth tokens) will
   silently follow to ``evil.com`` if you don't gate on origin.
   :class:`RedirectPolicy.same_origin_only` says "follow same-origin
   redirects, error on cross-origin". :class:`.deny` says "never
   follow; surface the 3xx to the caller".
2. **Authorization-header forwarding.** Even when a cross-origin
   redirect is intentional (image CDN with separate auth domain,
   for example), the Authorization header should not be forwarded
   to the new host by default — that's the requests-library
   default since 2014 and curl's --location-trusted behaviour
   inverts. :class:`.forward_auth_cross_origin` (default ``False``)
   controls this.
3. **307 / 308 method preservation.** RFC 9110 §15.4 mandates
   that 307 / 308 redirects preserve the original method + body
   (whereas 301 / 302 / 303 historically degrade POST → GET).
   The default policy honours this; the :func:`.decide` helper
   is the single source of truth.

Public surface:

- :class:`RedirectPolicy` — the policy struct (max hops + cross-
  origin gating + auth-forwarding gating).
- :class:`RedirectAction` — the three-way decision: ``Follow``,
  ``Stop`` (cap hit / DENY rule), or ``Reject`` (cross-origin
  while in SAME_ORIGIN mode).
- :class:`RedirectDecision` — the decision plus its derived
  next-request shape (method + whether to forward the Authorization
  header).

The decision-helper :meth:`RedirectPolicy.decide` is pure (no
network), so the v0.6 :class:`HttpClient` can be retrofitted onto
it in a follow-up commit without touching the policy logic. It
also makes the policy unit-testable in isolation, which is the
entire point — each cross-origin / auth-forwarding rule has an
explicit assertion in :mod:`tests.test_redirect_policy`.

Example:

```mojo
from flare.http import (
    HttpClient, RedirectPolicy, RedirectMode,
)

# Restrict redirects to the same origin (scheme + host + port);
# refuse to forward Authorization across origins.
var pol = RedirectPolicy.same_origin_only(max_redirects=5)

# Equivalent open-redirect-tolerant configuration (the v0.6
# default, byte-for-byte):
var pol_v06 = RedirectPolicy.follow_all(max_redirects=10)
```
"""

from .url import Url


# ── Mode ────────────────────────────────────────────────────────────────────


struct RedirectMode:
    """Cross-origin policy as a small enum-shaped namespace.

    Mojo doesn't ship an ``enum`` keyword on this nightly; we
    expose the constants as ``Int`` aliases so callers can
    pattern-match in plain ``if`` chains.
    """

    comptime FOLLOW_ALL: Int = 0
    """Follow any 3xx with a Location header, no origin gating.
    The v0.6 ``HttpClient`` default — preserves byte-for-byte
    behaviour."""

    comptime SAME_ORIGIN_ONLY: Int = 1
    """Follow only when the redirect target shares scheme + host
    + port with the previous request. Cross-origin redirects
    raise ``CrossOriginRedirect`` (mapped to ``HttpError`` at
    the client surface)."""

    comptime DENY: Int = 2
    """Never follow. The 3xx response is surfaced to the caller
    unchanged (status + Location header). Useful when the
    application wants to inspect the redirect target before
    deciding."""


# ── Action ──────────────────────────────────────────────────────────────────


struct RedirectAction:
    """Decision outcome from :meth:`RedirectPolicy.decide`."""

    comptime FOLLOW: Int = 0
    """Follow the redirect; the :class:`RedirectDecision`'s
    ``next_method`` / ``next_url`` / ``forward_authorization``
    fields apply."""

    comptime STOP: Int = 1
    """Stop following — either max-hops reached, or the policy
    is :data:`RedirectMode.DENY`. The caller surfaces the
    current 3xx response to the application."""

    comptime REJECT: Int = 2
    """Reject — the policy is :data:`RedirectMode.SAME_ORIGIN_ONLY`
    and the target was cross-origin. The caller raises
    :class:`CrossOriginRedirect` (mapped to ``HttpError``)."""


# ── Decision ────────────────────────────────────────────────────────────────


@fieldwise_init
struct RedirectDecision(Copyable, Movable):
    """The full output of :meth:`RedirectPolicy.decide`.

    Fields:
        action: One of :data:`RedirectAction.FOLLOW` /
            ``STOP`` / ``REJECT``.
        next_method: HTTP method for the next request (only
            populated when ``action == FOLLOW``). ``""`` for
            STOP / REJECT.
        next_url: Absolute URL for the next request (only
            populated when ``action == FOLLOW``). ``""`` for
            STOP / REJECT.
        next_body_dropped: When ``True``, the next request
            should drop its body (POST/PUT/PATCH → GET on
            301/302/303). When ``False``, the body is preserved
            (307/308 method-preserving redirect).
        forward_authorization: Whether the Authorization header
            should be forwarded to ``next_url`` (only meaningful
            when ``action == FOLLOW``). ``False`` for any
            cross-origin redirect under the default policy.
    """

    var action: Int
    var next_method: String
    var next_url: String
    var next_body_dropped: Bool
    var forward_authorization: Bool


# ── Origin helpers ──────────────────────────────────────────────────────────


def _resolve_location(base_url: String, location: String) raises -> String:
    """Resolve a Location header value to an absolute URL.

    Accepts:
    - Absolute URLs (``http://...`` / ``https://...``).
    - Origin-relative URLs (``/path?query``).
    - Relative URLs without a leading slash (resolved against
      base's directory — rare in practice but RFC-allowed).

    Raises ``Error`` on a malformed Location.
    """
    if location.byte_length() == 0:
        raise Error("RedirectPolicy: empty Location header")
    if location.startswith("http://") or location.startswith("https://"):
        return location
    var base = Url.parse(base_url)
    var origin = base.scheme + "://" + base.host + ":" + String(Int(base.port))
    if Int(location.unsafe_ptr()[0]) == ord("/"):
        return origin + location
    # Relative without leading slash — resolve against base's
    # request-target without the trailing filename segment.
    var target = base.request_target()
    var slash = target.byte_length()
    var p = target.unsafe_ptr()
    for i in range(target.byte_length()):
        if Int(p[target.byte_length() - 1 - i]) == ord("/"):
            slash = target.byte_length() - i
            break
    var dir = String(capacity=slash + 1)
    for i in range(slash):
        dir += chr(Int(p[i]))
    return origin + dir + location


def _same_origin(a_url: String, b_url: String) raises -> Bool:
    """RFC 6454 same-origin: scheme + host + port match."""
    var a = Url.parse(a_url)
    var b = Url.parse(b_url)
    if a.scheme != b.scheme:
        return False
    if a.host != b.host:
        return False
    if a.port != b.port:
        return False
    return True


# ── Policy ──────────────────────────────────────────────────────────────────


@fieldwise_init
struct RedirectPolicy(Copyable, Defaultable, Movable):
    """Configurable redirect-following policy.

    Fields:
        max_redirects: Hard cap on the redirect chain length.
            Hit → ``RedirectAction.STOP``.
        mode: One of :data:`RedirectMode.FOLLOW_ALL`,
            ``SAME_ORIGIN_ONLY``, or ``DENY``.
        forward_auth_cross_origin: Whether to forward the
            Authorization header on a cross-origin redirect.
            Defaults to ``False`` (security default; matches the
            requests-library default since 2014). Setting this
            ``True`` is the equivalent of curl's
            ``--location-trusted`` flag — only do it when both
            origins are under your control.

    Construct via the named factories rather than the raw
    ``__init__`` for readable call sites:

        ``RedirectPolicy.follow_all()``        # v0.6 default
        ``RedirectPolicy.same_origin_only()``  # security-default
        ``RedirectPolicy.deny()``              # never follow
    """

    var max_redirects: Int
    var mode: Int
    var forward_auth_cross_origin: Bool

    def __init__(out self):
        """Default policy: matches v0.6 ``HttpClient`` behaviour
        (FOLLOW_ALL, max_redirects=10, no auth forwarding to
        cross-origin)."""
        self.max_redirects = 10
        self.mode = RedirectMode.FOLLOW_ALL
        self.forward_auth_cross_origin = False

    @staticmethod
    def follow_all(max_redirects: Int = 10) -> RedirectPolicy:
        """Follow every 3xx with a Location header, up to
        ``max_redirects`` hops. Authorization is NOT forwarded
        cross-origin (security default)."""
        return RedirectPolicy(
            max_redirects=max_redirects,
            mode=RedirectMode.FOLLOW_ALL,
            forward_auth_cross_origin=False,
        )

    @staticmethod
    def same_origin_only(max_redirects: Int = 10) -> RedirectPolicy:
        """Follow only same-origin redirects (scheme + host +
        port). Cross-origin → ``RedirectAction.REJECT``."""
        return RedirectPolicy(
            max_redirects=max_redirects,
            mode=RedirectMode.SAME_ORIGIN_ONLY,
            forward_auth_cross_origin=False,
        )

    @staticmethod
    def deny() -> RedirectPolicy:
        """Never follow. Always returns ``RedirectAction.STOP``."""
        return RedirectPolicy(
            max_redirects=0,
            mode=RedirectMode.DENY,
            forward_auth_cross_origin=False,
        )

    def decide(
        self,
        current_url: String,
        current_method: String,
        status: Int,
        location: String,
        hops_so_far: Int,
    ) raises -> RedirectDecision:
        """Compute the redirect decision for one 3xx response.

        Args:
            current_url: Absolute URL the previous request hit.
            current_method: HTTP method of the previous request
                (uppercase, e.g. ``"POST"``).
            status: 3xx status code from the previous response.
            location: Raw ``Location`` header value (may be
                relative; resolved against ``current_url``).
            hops_so_far: Count of redirects already followed in
                this chain (excluding this one).

        Returns:
            A :class:`RedirectDecision` describing how the
            caller should proceed.

        Raises:
            Error: On a malformed Location header.
        """
        # Hard floor: empty Location means "no redirect target",
        # caller must STOP.
        if location.byte_length() == 0:
            return RedirectDecision(
                RedirectAction.STOP, String(""), String(""), False, True
            )

        # DENY: never follow.
        if self.mode == RedirectMode.DENY:
            return RedirectDecision(
                RedirectAction.STOP, String(""), String(""), False, True
            )

        # Hops cap.
        if hops_so_far >= self.max_redirects:
            return RedirectDecision(
                RedirectAction.STOP, String(""), String(""), False, True
            )

        var next_url = _resolve_location(current_url, location)

        # Origin gating.
        var same_origin = _same_origin(current_url, next_url)
        if self.mode == RedirectMode.SAME_ORIGIN_ONLY and not same_origin:
            return RedirectDecision(
                RedirectAction.REJECT,
                String(""),
                String(""),
                False,
                False,
            )

        # Method + body handling per RFC 9110 §15.4:
        # - 301 / 302 / 303 with a non-GET / non-HEAD method:
        #   degrade to GET, drop body. (303 spec-mandates GET; 301 +
        #   302 are "historical practice" but every practical client
        #   does the same to avoid round-tripping POST bodies through
        #   redirects that point at a results page.)
        # - 307 / 308: preserve method + body verbatim (the spec's
        #   reason these codes exist).
        var next_method = current_method
        var body_dropped = False
        var is_safe = current_method == "GET" or current_method == "HEAD"
        if not is_safe and (status == 301 or status == 302 or status == 303):
            next_method = String("GET")
            body_dropped = True

        # Auth forwarding: forward iff same-origin OR opt-in.
        var fwd_auth = same_origin or self.forward_auth_cross_origin

        return RedirectDecision(
            RedirectAction.FOLLOW,
            next_method^,
            next_url^,
            body_dropped,
            fwd_auth,
        )
