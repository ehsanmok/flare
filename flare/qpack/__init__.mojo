"""``flare.qpack`` -- QPACK encoder/decoder (RFC 9204).

HTTP/3 uses QPACK on top of QUIC streams. This package ships:

- The static-table field-section codec (:mod:`.codec`): the wire shapes
  that reference the RFC 9204 Appendix A static table plus literal field
  lines. This is the HoL-blocking-free default the h3 server encodes
  with.
- The dynamic table (:mod:`.dynamic`): the per-connection insert log
  streamed over the QPACK encoder stream, the decoder-stream
  acknowledgements, and the field-section shapes that reference dynamic
  entries by relative / post-base index. The h3 server applies inbound
  encoder-stream inserts into a :struct:`QpackDecoder` and decodes
  request field sections against it.

The codec lives entirely in the sans-I/O sublayer; tests live in
``tests/qpack/`` and the H3 frame layer (``flare.http3``) is the call site
that consumes it.
"""

from .codec import (
    QpackHeader,
    decode_field_section,
    encode_field_section,
)
from .dynamic import (
    QpackDecoder,
    QpackDynamicTable,
    QpackEncoder,
    apply_encoder_instructions,
    apply_encoder_instructions_partial,
    decode_field_section_dynamic,
    decode_required_insert_count,
    encode_field_section_dynamic,
    encode_insert_count_increment,
    encode_insert_with_literal_name,
    encode_insert_with_name_ref,
    encode_required_insert_count,
    encode_section_ack,
    encode_set_capacity,
    entry_size,
    parse_decoder_instruction,
)
from .static_table import (
    QPACK_STATIC_TABLE_SIZE,
    static_table_find,
    static_table_find_name,
    static_table_lookup,
)
