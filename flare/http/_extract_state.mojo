"""``State[T]`` -- registration-time injection field for ``Extracted[H]``.

Split out of ``flare/http/extract.mojo`` to keep that module under the
file-size budget; ``flare.http.extract`` re-exports :class:`State` so
``from flare.http import State`` keeps resolving.
"""

from ._extract_core import Extractor
from .request import Request


struct State[T: Copyable & Defaultable & ImplicitlyDestructible & Movable](
    Copyable, Defaultable, Extractor, Movable
):
    """A handler field carrying registration-time state, not request data.

    ``State[T]`` is a no-op :trait:`Extractor`: its ``apply`` reads
    nothing from the request, so the value set when the handler
    prototype was registered survives ``Extracted[H]``'s per-request
    prototype copy. Use it for shared, request-independent state -- a
    DB pool, config, a cache handle -- next to the request-derived
    extractor fields. The direct analogue of axum's ``State(db)``.

    ``T`` must be ``Copyable & Defaultable & Movable`` (the same bound
    the enclosing handler struct needs). See :class:`Extracted` for a
    full registration example.
    """

    var value: Self.T

    def __init__(out self):
        self.value = Self.T()

    def __init__(out self, var value: Self.T):
        self.value = value^

    def apply(mut self, req: Request) raises:
        # Registration-time state; nothing is read from the request.
        pass
