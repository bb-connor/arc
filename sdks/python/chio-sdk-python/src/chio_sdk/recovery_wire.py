"""Allocation bounds for foundation JSON. This module grants no authority."""
from __future__ import annotations

import json
import math
import re
from decimal import Decimal, InvalidOperation

MAX_WIRE_BYTES = 65536
MAX_DEPTH = 16
MAX_NODES = 4096
MAX_CONTAINER_ENTRIES = 256
MAX_ENCODED_STRING_BYTES = 32768
MAX_SAFE_INTEGER = 9007199254740991
MAX_RESPONSE_BYTES = 262144
MAX_RESPONSE_DEPTH = 64
_NUMBER_TOKEN = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", re.ASCII)
_INTEGER_TOKEN = re.compile(r"-?(?:0|[1-9][0-9]*)", re.ASCII)
_UNSIGNED_TOKEN = re.compile(r"(?:0|[1-9][0-9]*)", re.ASCII)
_OPAQUE_PATH = ("original_response", "result")
_RECEIPT_JSON_PATHS = {
    ("original_response", "receipt", "metadata"),
    ("original_response", "receipt", "action", "parameters"),
}


class LosslessJsonNumber:
    """An immutable opaque JSON numeric lexeme requiring explicit conversion.

    Ordinary JSON and Pydantic serialization refuse this object. Preserve
    ``source`` when carrying exact tool data; none of these conversions grant
    receipt, signature or execution authority.
    """

    __slots__ = ("_source",)

    def __init__(self, source: str):
        if type(source) is not str or len(source) > MAX_RESPONSE_BYTES or _NUMBER_TOKEN.fullmatch(source) is None:
            raise ValueError("invalid JSON number token")
        object.__setattr__(self, "_source", source)

    def __setattr__(self, name, value):
        raise AttributeError("JSON number tokens are immutable")

    def __delattr__(self, name):
        raise AttributeError("JSON number tokens are immutable")

    @property
    def source(self) -> str:
        return self._source

    def to_decimal(self) -> Decimal:
        try:
            return Decimal(self.source)
        except (InvalidOperation, OverflowError):
            raise ValueError("JSON number cannot be represented as a Decimal") from None

    def to_int(self) -> int:
        if _INTEGER_TOKEN.fullmatch(self.source) is None:
            raise ValueError("JSON number is not an integer literal")
        return int(self.source)

    def to_float(self) -> float:
        value = float(self.source)
        if not math.isfinite(value) or self.to_decimal() != Decimal(repr(value)):
            raise ValueError("JSON number cannot be converted without losing precision")
        return value


def require_utf8_bound(value: str, maximum: int) -> str:
    if len(value.encode("utf-8")) > maximum:
        raise ValueError("recovery protected text exceeds its UTF-8 byte bound")
    return value


def _reject_constant(_: str):
    raise ValueError("non-JSON numeric constant")


def _require_scalar_strings(value: object) -> None:
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, list):
        for item in value:
            _require_scalar_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            _require_scalar_strings(item)


def _require_unsigned_number(token: str) -> None:
    if _UNSIGNED_TOKEN.fullmatch(token) is None:
        raise ValueError("recovery metadata requires an unsigned canonical integer token")
    if len(token) > 16 or int(token) > MAX_SAFE_INTEGER:
        raise ValueError("unsafe recovery integer")


def _scan_wire(wire: bytes, *, response: bool = False, unsigned: bool = True) -> None:
    """Bound allocation before parsing; response mode exempts opaque budgets."""
    if not wire or len(wire) > (MAX_RESPONSE_BYTES if response else MAX_WIRE_BYTES):
        raise ValueError("recovery foundation byte bound")
    cursor = nodes = strings = 0
    entries: list[int] = []
    while cursor < len(wire):
        byte = wire[cursor]
        if byte in b" \n\r\t:":
            cursor += 1
            continue
        if byte in b"{[":
            nodes += 1
            if len(entries) >= (MAX_RESPONSE_DEPTH if response else MAX_DEPTH):
                raise ValueError("recovery foundation depth bound")
            entries.append(1)
            cursor += 1
        elif byte in b"}]":
            if not entries:
                raise ValueError("malformed recovery container")
            entries.pop()
            cursor += 1
        elif byte == ord(","):
            if not entries:
                raise ValueError("malformed recovery separator")
            entries[-1] += 1
            if not response and entries[-1] > MAX_CONTAINER_ENTRIES:
                raise ValueError("recovery foundation container bound")
            cursor += 1
        elif byte == ord('"'):
            nodes += 1
            cursor += 1
            start = cursor
            while cursor < len(wire) and wire[cursor] != ord('"'):
                cursor += 2 if wire[cursor] == ord("\\") else 1
                if not response and strings + cursor - start > MAX_ENCODED_STRING_BYTES:
                    raise ValueError("recovery foundation encoded-string bound")
            if cursor >= len(wire):
                raise ValueError("unterminated recovery string")
            strings += cursor - start
            cursor += 1
        else:
            nodes += 1
            start = cursor
            while cursor < len(wire) and wire[cursor] not in b",}] \n\r\t":
                cursor += 1
            token = wire[start:cursor]
            if unsigned and token not in (b"true", b"false", b"null"):
                _require_unsigned_number(token.decode("ascii"))
        if not response and nodes > MAX_NODES:
            raise ValueError("recovery foundation node bound")
    if entries:
        raise ValueError("incomplete recovery container")


class _RawReader:
    """Read prebounded JSON without numeric conversions or member collapse."""

    def __init__(self, source: str):
        self.source = source
        self.cursor = 0
        self.opaque_span: tuple[int, int] | None = None
        self.decoder = json.JSONDecoder(parse_int=LosslessJsonNumber, parse_float=LosslessJsonNumber,
                                        parse_constant=_reject_constant)

    def _space(self) -> None:
        while self.cursor < len(self.source) and self.source[self.cursor] in " \n\r\t":
            self.cursor += 1

    def _take(self, token: str) -> bool:
        self._space()
        if self.cursor < len(self.source) and self.source[self.cursor] == token:
            self.cursor += 1
            return True
        return False

    def read(self) -> object:
        value = self._value(())
        self._space()
        if self.cursor != len(self.source):
            raise ValueError("trailing recovery JSON data")
        _require_scalar_strings(value)
        return value

    def _value(self, path: tuple[str | int, ...]) -> object:
        self._space()
        start = self.cursor
        if self._take("{"):
            value = {}
            if not self._take("}"):
                while True:
                    self._space()
                    key, self.cursor = self.decoder.raw_decode(self.source, self.cursor)
                    if not isinstance(key, str) or key in value:
                        raise ValueError("invalid or duplicate recovery JSON member")
                    if not self._take(":"):
                        raise ValueError("missing recovery JSON member separator")
                    value[key] = self._value(path + (key,))
                    if self._take("}"):
                        break
                    if not self._take(","):
                        raise ValueError("invalid recovery JSON object separator")
        elif self._take("["):
            value = []
            if not self._take("]"):
                while True:
                    value.append(self._value(path + (len(value),)))
                    if self._take("]"):
                        break
                    if not self._take(","):
                        raise ValueError("invalid recovery JSON array separator")
        else:
            value, self.cursor = self.decoder.raw_decode(self.source, self.cursor)
        if path == _OPAQUE_PATH:
            self.opaque_span = (start, self.cursor)
        return value


def _require_receipt_number(token: str) -> None:
    if _INTEGER_TOKEN.fullmatch(token) is not None:
        if len(token.lstrip("-")) > 16 or abs(int(token)) > MAX_SAFE_INTEGER or str(int(token)) != token:
            raise ValueError("receipt JSON integer is outside the canonical I-JSON domain")
        return
    value = float(token)
    if not math.isfinite(value) or value.is_integer():
        raise ValueError("receipt JSON float is non-finite or integer-valued")
    shortest = repr(value)
    if 1e-6 <= abs(value) < 1e21:
        canonical = format(Decimal(shortest), "f")
    else:
        mantissa, exponent = shortest.split("e")
        power = int(exponent)
        canonical = mantissa + "e" + ("+" if power >= 0 else "") + str(power)
    if canonical != token:
        raise ValueError("receipt JSON fraction is not exact canonical I-JSON")


def _require_response_numbers(value: object, path: tuple[str | int, ...] = (), *,
                              opaque_result: bool, receipt_json: bool = False) -> None:
    if opaque_result and path == _OPAQUE_PATH:
        return
    receipt_json = receipt_json or (opaque_result and path in _RECEIPT_JSON_PATHS)
    if isinstance(value, LosslessJsonNumber):
        (_require_receipt_number if receipt_json else _require_unsigned_number)(value.source)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _require_response_numbers(item, path + (index,), opaque_result=opaque_result, receipt_json=receipt_json)
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_response_numbers(item, path + (key,), opaque_result=opaque_result, receipt_json=receipt_json)


def assert_foundation_wire(source: str) -> None:
    """Charge raw unsigned foundation budgets before syntax/member validation.

    Protected embedded strings retain their bytes for their owning decoder.
    Field shape, signatures and freshness remain separate checks.
    """
    _scan_wire(source.encode("utf-8"))
    _RawReader(source).read()


def read_response_wire(source: bytes | bytearray, *, opaque_result: bool = False) -> tuple[object, bytes]:
    """Preflight exact raw response bytes before generated JSON validation.

    Only the existing opaque tool result is replaced in the resource projection.
    Every other byte, including encoded strings and original numeric lexemes,
    remains charged unchanged. This reader establishes no signature authority.
    """
    return _read_response_wire(source, opaque_result=opaque_result, foundation=True)


def read_product_view_wire(source: bytes | bytearray) -> tuple[object, bytes]:
    """Read a native product projection within its complete response budget.

    Product labels can exceed the foundation command's aggregate string budget.
    The native 256 KiB byte and 64-level depth ceilings bound allocation; raw
    numeric, Unicode and member checks still apply before typed validation.
    """
    return _read_response_wire(source, opaque_result=False, foundation=False)


def _read_response_wire(source: bytes | bytearray, *, opaque_result: bool,
                        foundation: bool) -> tuple[object, bytes]:
    _scan_wire(source, response=True, unsigned=False)
    text = source.decode("utf-8")
    reader = _RawReader(text)
    value = reader.read()
    projection_source = text
    if opaque_result and reader.opaque_span is not None:
        start, end = reader.opaque_span
        projection_source = text[:start] + "null" + text[end:]
    projection = projection_source.encode("utf-8")
    if foundation:
        _scan_wire(projection, unsigned=False)
    _require_response_numbers(value, opaque_result=opaque_result)
    return value, projection


def retain_opaque_json(value: object) -> object:
    """Retain Python integer literals and exact opaque float/exponent tokens."""
    if isinstance(value, LosslessJsonNumber):
        if value.source != "-0" and _INTEGER_TOKEN.fullmatch(value.source) is not None:
            try:
                return value.to_int()
            except ValueError:
                # Python's configured integer-digit ceiling is a consumer
                # conversion limit, not permission to round or reject JSON.
                pass
        return value
    if isinstance(value, list):
        return [retain_opaque_json(item) for item in value]
    if isinstance(value, dict):
        return {key: retain_opaque_json(item) for key, item in value.items()}
    return value
