#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Nicolas Iooss, SUTD
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Useful routines and utilities which simplify code writing"""
from typing import Optional, Tuple

from scapy import all as scapy_all


def hexdump(data, columns=16, indentlvl=""):
    """Return the hexadecimal representation of the data."""

    def do_line(line):
        return (
            indentlvl
            + " ".join(f"{byte:02x}" for byte in line)
            + "   " * (columns - len(line))
            + "  "
            + "".join(chr(byte) if 32 <= byte < 127 else "." for byte in line)
        )

    if isinstance(data, str):
        data_bytes = data.encode("utf-8", errors="replace")
    else:
        data_bytes = bytes(data)

    return "\n".join(
        do_line(data_bytes[i : i + columns]) for i in range(0, len(data_bytes), columns)
    )


class LEShortLenField(scapy_all.FieldLenField):
    """A len field in a 2-byte integer"""

    def __init__(self, name, default, count_of=None, length_of=None):
        scapy_all.FieldLenField.__init__(self, name, default, fmt="<H",
                                         count_of=count_of, length_of=length_of)


class XBitEnumField(scapy_all.BitEnumField):
    """A BitEnumField with hexadecimal representation"""

    def __init__(self, name, default, size, enum):
        scapy_all.BitEnumField.__init__(self, name, default, size, enum)

    def i2repr_one(self, pkt, x):
        if x in self.i2s:
            return self.i2s[x]
        return scapy_all.lhex(x)


def cip_status_details(cippkt) -> Tuple[int, Optional[object]]:
    """Return a CIP status code and the corresponding status object.

    Some devices omit the response status list entirely, which previously
    triggered ``IndexError`` crashes when callers expected the first status to
    be present.  Normalise those "missing" cases to a success code (0) and
    surface the optional status structure for logging when it exists.
    """

    statuses = getattr(cippkt, "status", None) or []
    if not statuses:
        return 0, None

    status = statuses[0]
    code = getattr(status, "status", None)
    if code is None:
        return 0, status
    return code, status
