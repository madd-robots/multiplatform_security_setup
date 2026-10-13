# SPDX-License-Identifier: GPL-3.0-or-later
"""Small declarative validators for IPC messages and operation parameters.

Every value crossing a process boundary is checked against an explicit spec.
Objects reject unknown fields by default, and ``bool`` is never accepted
where an integer is expected.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Optional, Pattern

from ..common.errors import ValidationError
from ..common.text import display_text


class Spec:
    def check(self, value: Any, where: str) -> Any:
        raise NotImplementedError


class Str(Spec):
    def __init__(self, *, min_len: int = 0, max_len: int = 1024, pattern: Optional[str] = None):
        self.min_len = min_len
        self.max_len = max_len
        self.pattern: Optional[Pattern[str]] = re.compile(pattern) if pattern else None

    def check(self, value: Any, where: str) -> Any:
        if not isinstance(value, str):
            raise ValidationError("%s: expected a string" % where)
        if not self.min_len <= len(value) <= self.max_len:
            raise ValidationError("%s: length must be %d..%d" % (where, self.min_len, self.max_len))
        if self.pattern is not None and not self.pattern.fullmatch(value):
            raise ValidationError("%s: value %s has an invalid format" % (where, display_text(value, 60)))
        return value


class Int(Spec):
    def __init__(self, *, min_value: int, max_value: int):
        self.min_value = min_value
        self.max_value = max_value

    def check(self, value: Any, where: str) -> Any:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValidationError("%s: expected an integer" % where)
        if not self.min_value <= value <= self.max_value:
            raise ValidationError("%s: must be %d..%d" % (where, self.min_value, self.max_value))
        return value


class Bool(Spec):
    def check(self, value: Any, where: str) -> Any:
        if not isinstance(value, bool):
            raise ValidationError("%s: expected true or false" % where)
        return value


class Enum(Spec):
    def __init__(self, values: Iterable[str]):
        self.values = frozenset(values)

    def check(self, value: Any, where: str) -> Any:
        if not isinstance(value, str) or value not in self.values:
            raise ValidationError("%s: must be one of %s" % (where, ", ".join(sorted(self.values))))
        return value


class Const(Spec):
    def __init__(self, value: Any):
        self.value = value

    def check(self, value: Any, where: str) -> Any:
        if type(value) is not type(self.value) or value != self.value:
            raise ValidationError("%s: must be %r" % (where, self.value))
        return value


class List(Spec):
    def __init__(self, item: Spec, *, max_items: int = 256, min_items: int = 0, unique: bool = False):
        self.item = item
        self.max_items = max_items
        self.min_items = min_items
        self.unique = unique

    def check(self, value: Any, where: str) -> Any:
        if not isinstance(value, list):
            raise ValidationError("%s: expected a list" % where)
        if not self.min_items <= len(value) <= self.max_items:
            raise ValidationError("%s: must have %d..%d items" % (where, self.min_items, self.max_items))
        out = [self.item.check(v, "%s[%d]" % (where, i)) for i, v in enumerate(value)]
        if self.unique and len({repr(v) for v in out}) != len(out):
            raise ValidationError("%s: items must be unique" % where)
        return out


class Nullable(Spec):
    def __init__(self, inner: Spec):
        self.inner = inner

    def check(self, value: Any, where: str) -> Any:
        return None if value is None else self.inner.check(value, where)


class Any_(Spec):
    """Accept any value (already constrained by canonical decoding)."""

    def check(self, value: Any, where: str) -> Any:
        return value


class Obj(Spec):
    def __init__(self, fields: Dict[str, Spec], *, optional: Iterable[str] = (), allow_extra: bool = False):
        self.fields = dict(fields)
        self.optional = frozenset(optional)
        unknown = self.optional - set(self.fields)
        if unknown:
            raise ValueError("optional names unknown fields: %s" % sorted(unknown))
        self.allow_extra = allow_extra

    def check(self, value: Any, where: str) -> Any:
        if not isinstance(value, dict):
            raise ValidationError("%s: expected an object" % where)
        if not self.allow_extra:
            extra = set(value) - set(self.fields)
            if extra:
                raise ValidationError("%s: unexpected field %s" % (where, display_text(sorted(extra)[0], 60)))
        out = dict(value) if self.allow_extra else {}
        for name, spec in self.fields.items():
            if name not in value:
                if name in self.optional:
                    continue
                raise ValidationError("%s: missing field %s" % (where, name))
            out[name] = spec.check(value[name], "%s.%s" % (where, name))
        return out


def validate(spec: Spec, value: Any, where: str = "$") -> Any:
    return spec.check(value, where)


EMPTY = Obj({})
