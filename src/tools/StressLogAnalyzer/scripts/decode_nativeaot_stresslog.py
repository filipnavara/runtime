#!/usr/bin/env python3
# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.

"""Decode NativeAOT StressLog chunks dumped from a debugger.

The input directory must contain a stresslog-map.txt file plus chunk files
produced by dump_nativeaot_stresslog_gdb.py, dump_nativeaot_stresslog_lldb.py,
or the temporary NativeAOT in-process StressLog::DumpToDirectory helper used
during PPC64LE bring-up.

This is a lightweight decoder for offline triage. It resolves format strings
from the NativeAOT ELF image and prints a best-effort printf-style text form.
For memory-mapped stress logs, prefer src/tools/StressLogAnalyzer.
"""

from __future__ import annotations

import argparse
import bisect
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


POINTER_SIZE = 8
STRESS_MSG_SIZE = 16
MAX_ARG_COUNT = 63
MAX_MSG_SIZE = STRESS_MSG_SIZE + MAX_ARG_COUNT * POINTER_SIZE
CHUNK_HEADER_SIZE = 16
CHUNK_TRAILER_SIZE = 8
CHUNK_SIGNATURE = 0xCFCFCFCF


def parse_int(value: str) -> int:
    return int(value, 0)


@dataclass
class Chunk:
    index: int
    address: int
    prev: int
    next: int
    file: Path
    data: bytes
    buffer_size: int

    @property
    def start(self) -> int:
        return self.address + CHUNK_HEADER_SIZE

    @property
    def end(self) -> int:
        return self.start + self.buffer_size

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end

    def read(self, address: int, size: int) -> bytes:
        offset = address - self.address
        if offset < 0 or offset + size > len(self.data):
            raise ValueError(f"address 0x{address:x} is outside chunk 0x{self.address:x}")
        return self.data[offset : offset + size]


@dataclass
class ThreadLog:
    index: int
    address: int
    values: dict[str, int] = field(default_factory=dict)
    chunks: list[Chunk] = field(default_factory=list)


@dataclass
class Capture:
    directory: Path
    values: dict[str, int]
    threads: list[ThreadLog]


@dataclass(order=True)
class Message:
    timestamp: int
    thread_id: int
    facility: int
    format_offset: int
    args: list[int]
    text: str


class ElfImage:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        self.loads: list[tuple[int, int, int]] = []
        self._parse()

    def _parse(self) -> None:
        ident = self.data[:16]
        if len(ident) != 16 or ident[:4] != b"\x7fELF":
            raise ValueError(f"{self.path} is not an ELF file")
        if ident[4] != 2:
            raise ValueError("only ELF64 images are supported")
        if ident[5] == 1:
            endian = "<"
        elif ident[5] == 2:
            endian = ">"
        else:
            raise ValueError("unknown ELF endianness")

        header = struct.unpack_from(endian + "HHIQQQIHHHHHH", self.data, 16)
        phoff = header[4]
        phentsize = header[8]
        phnum = header[9]
        for i in range(phnum):
            offset = phoff + i * phentsize
            p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = struct.unpack_from(
                endian + "IIQQQQQQ", self.data, offset
            )
            if p_type == 1 and p_filesz != 0:
                self.loads.append((p_vaddr, p_vaddr + p_filesz, p_offset))

        self.loads.sort()

    def read_c_string_at_rva(self, rva: int, limit: int = 4096) -> str:
        for start, end, file_offset in self.loads:
            if start <= rva < end:
                offset = file_offset + (rva - start)
                raw = self.data[offset : min(offset + limit, file_offset + (end - start))]
                raw = raw.split(b"\0", 1)[0]
                return raw.decode("utf-8", errors="replace")
        return f"<format@0x{rva:x}>"


def parse_map(directory: Path) -> Capture:
    map_path = directory / "stresslog-map.txt"
    values: dict[str, int] = {}
    threads: list[ThreadLog] = []
    current: ThreadLog | None = None

    key_re = re.compile(r"^([A-Za-z][A-Za-z0-9]*)=(.+)$")
    thread_re = re.compile(r"^thread\[(\d+)\] addr=(0x[0-9a-fA-F]+)")
    chunk_re = re.compile(
        r"^chunk\[(\d+)\] addr=(0x[0-9a-fA-F]+) prev=(0x[0-9a-fA-F]+) "
        r"next=(0x[0-9a-fA-F]+) file=(.+)$"
    )

    for raw_line in map_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if match := thread_re.match(line):
            current = ThreadLog(index=int(match.group(1)), address=parse_int(match.group(2)))
            threads.append(current)
            continue

        if current is not None and (match := chunk_re.match(line)):
            chunk_file = directory / match.group(5)
            data = chunk_file.read_bytes()
            if len(data) >= CHUNK_HEADER_SIZE + CHUNK_TRAILER_SIZE:
                sig1 = struct.unpack_from("<I", data, len(data) - 8)[0]
                sig2 = struct.unpack_from("<I", data, len(data) - 4)[0]
                if sig1 != CHUNK_SIGNATURE or sig2 != CHUNK_SIGNATURE:
                    print(f"warning: chunk {chunk_file} has unexpected signature", file=sys.stderr)
            current.chunks.append(
                Chunk(
                    index=int(match.group(1)),
                    address=parse_int(match.group(2)),
                    prev=parse_int(match.group(3)),
                    next=parse_int(match.group(4)),
                    file=chunk_file,
                    data=data,
                    buffer_size=max(0, len(data) - CHUNK_HEADER_SIZE - CHUNK_TRAILER_SIZE),
                )
            )
            continue

        if match := key_re.match(line):
            key, value = match.groups()
            try:
                parsed = parse_int(value)
            except ValueError:
                continue
            if current is None:
                values[key] = parsed
            else:
                current.values[key] = parsed

    return Capture(directory=directory, values=values, threads=threads)


def chunk_for_address(chunks_by_address: dict[int, Chunk], address: int) -> Chunk | None:
    for chunk in chunks_by_address.values():
        if chunk.contains(address):
            return chunk
    return None


def find_first_message_in_chunk(chunk: Chunk) -> int:
    scan_end = min(chunk.start + MAX_MSG_SIZE, chunk.end)
    ptr = chunk.start
    while ptr + POINTER_SIZE <= scan_end:
        if struct.unpack_from("<Q", chunk.read(ptr, POINTER_SIZE))[0] != 0:
            return ptr
        ptr += POINTER_SIZE
    return chunk.start


def decode_header(chunk: Chunk, address: int) -> tuple[int, int, int, int]:
    payload1, payload2 = struct.unpack_from("<QQ", chunk.read(address, STRESS_MSG_SIZE))
    facility = payload1 & 0xFFFFFFFF
    number_of_args = (payload1 >> 32) & 0x3F
    format_low = (payload1 >> 38) & ((1 << 26) - 1)
    format_high = payload2 & ((1 << 13) - 1)
    format_offset = format_low | (format_high << 26)
    timestamp = payload2 >> 13
    return facility, number_of_args, format_offset, timestamp


def read_args(chunk: Chunk, address: int, number_of_args: int) -> list[int]:
    args = []
    arg_base = address + STRESS_MSG_SIZE
    for i in range(number_of_args):
        args.append(struct.unpack_from("<Q", chunk.read(arg_base + i * POINTER_SIZE, POINTER_SIZE))[0])
    return args


def signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def signed64(value: int) -> int:
    value &= 0xFFFFFFFFFFFFFFFF
    return value - 0x10000000000000000 if value & 0x8000000000000000 else value


def format_message(format_string: str, args: list[int]) -> str:
    result: list[str] = []
    index = 0
    arg_index = 0

    while index < len(format_string):
        percent = format_string.find("%", index)
        if percent < 0:
            result.append(format_string[index:])
            break
        result.append(format_string[index:percent])
        index = percent + 1
        if index >= len(format_string):
            result.append("%")
            break
        if format_string[index] == "%":
            result.append("%")
            index += 1
            continue

        alternate = False
        if format_string[index] == "#":
            alternate = True
            index += 1

        pad = ""
        if index < len(format_string) and format_string[index] == "0":
            pad = "0"
            index += 1
        width_digits = []
        while index < len(format_string) and format_string[index].isdigit():
            width_digits.append(format_string[index])
            index += 1
        width = int("".join(width_digits)) if width_digits else 0

        if index < len(format_string) and format_string[index] == ".":
            index += 1
            while index < len(format_string) and format_string[index].isdigit():
                index += 1

        length = ""
        if format_string.startswith("I64", index):
            length = "I64"
            index += 3
        elif index < len(format_string) and format_string[index] in "hlzI":
            length = format_string[index]
            index += 1
            if length == "l" and index < len(format_string) and format_string[index] == "l":
                length = "ll"
                index += 1

        if index >= len(format_string):
            result.append("%")
            break

        spec = format_string[index]
        index += 1
        if spec == "p" and index < len(format_string) and format_string[index] in "MTVK":
            spec += format_string[index]
            index += 1

        if arg_index >= len(args):
            result.append(f"%{length}{spec}<missing>")
            continue

        arg = args[arg_index]
        arg_index += 1

        if spec in ("p", "pM", "pT", "pV", "pK"):
            result.append(f"0x{arg:016x}")
        elif spec in ("d", "i"):
            value = signed64(arg) if length in ("ll", "I64", "z", "I") else signed32(arg)
            result.append(f"{value:{pad}{width}d}" if width else str(value))
        elif spec == "u":
            result.append(f"{arg:{pad}{width}d}" if width else str(arg))
        elif spec in ("x", "X"):
            prefix = "0x" if alternate else ""
            fmt = spec
            value = f"{arg:{pad}{width}{fmt}}" if width else f"{arg:{fmt}}"
            result.append(prefix + value)
        elif spec in ("s", "S") or (length in ("h", "l") and spec == "s"):
            result.append(f"<string@0x{arg:x}>")
        elif spec == "f":
            result.append(str(struct.unpack("<d", struct.pack("<Q", arg))[0]))
        else:
            result.append(f"%{length}{spec}(0x{arg:x})")

    return "".join(result)


def enumerate_thread_messages(thread: ThreadLog, image: ElfImage) -> Iterable[Message]:
    chunks_by_address = {chunk.address: chunk for chunk in thread.chunks}
    if not chunks_by_address:
        return

    current = chunks_by_address.get(thread.values.get("curWriteChunk", 0))
    if current is None:
        current = chunk_for_address(chunks_by_address, thread.values.get("curPtr", 0))
    if current is None:
        return

    read_ptr = thread.values.get("curPtr", 0)
    if read_ptr == 0:
        return

    safe_cur_ptr = max(read_ptr - MAX_MSG_SIZE, current.start)
    read_has_wrapped = False
    write_has_wrapped = thread.values.get("writeHasWrapped", 0) != 0
    tail = thread.values.get("chunkListTail", 0)
    cur_write_chunk = thread.values.get("curWriteChunk", 0)

    def advance_past_boundary() -> None:
        nonlocal current, read_ptr, read_has_wrapped
        if current.address == tail:
            read_has_wrapped = True
            if not write_has_wrapped:
                return
        next_chunk = chunks_by_address.get(current.next)
        if next_chunk is None:
            read_ptr = current.end
            return
        current = next_chunk
        read_ptr = find_first_message_in_chunk(current)

    if read_ptr == current.end:
        advance_past_boundary()

    seen_positions: set[tuple[int, int]] = set()
    while True:
        if not current.contains(read_ptr):
            break
        if (current.address, read_ptr) in seen_positions:
            break
        seen_positions.add((current.address, read_ptr))

        facility, number_of_args, format_offset, timestamp = decode_header(current, read_ptr)
        if timestamp == 0:
            break
        if read_has_wrapped and (not write_has_wrapped or (current.address == cur_write_chunk and read_ptr >= safe_cur_ptr)):
            break
        if number_of_args > MAX_ARG_COUNT:
            break

        args = read_args(current, read_ptr, number_of_args)
        if format_offset != 0:
            format_string = image.read_c_string_at_rva(format_offset)
            text = format_message(format_string, args)
            yield Message(timestamp, thread.values.get("threadId", 0), facility, format_offset, args, text)

        read_ptr += STRESS_MSG_SIZE + number_of_args * POINTER_SIZE
        if read_ptr >= current.end:
            advance_past_boundary()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_dir", type=Path, help="Directory containing stresslog-map.txt and chunk .bin files")
    parser.add_argument("--module", "-m", type=Path, required=True, help="NativeAOT ELF image used to resolve format strings")
    parser.add_argument("--output", "-o", type=Path, help="Write decoded log to this file")
    parser.add_argument("--grep", "-g", action="append", default=[], help="Only print messages containing this string")
    parser.add_argument("--limit", "-n", type=int, default=0, help="Maximum number of messages to print")
    args = parser.parse_args(argv)

    capture = parse_map(args.capture_dir)
    image = ElfImage(args.module)

    messages: list[Message] = []
    for thread in capture.threads:
        messages.extend(enumerate_thread_messages(thread, image) or [])
    messages.sort(key=lambda message: (message.timestamp, message.thread_id), reverse=True)

    filters = [needle.lower() for needle in args.grep]
    if filters:
        messages = [message for message in messages if all(needle in message.text.lower() for needle in filters)]
    if args.limit:
        messages = messages[: args.limit]

    output = sys.stdout
    close_output = False
    if args.output is not None:
        output = args.output.open("w", encoding="utf-8")
        close_output = True
    try:
        tick_frequency = capture.values.get("tickFrequency", 0)
        start_timestamp = capture.values.get("startTimeStamp", 0)
        for message in messages:
            if tick_frequency:
                seconds = (message.timestamp - start_timestamp) / tick_frequency
                prefix = f"{seconds:12.6f}s"
            else:
                prefix = f"ts={message.timestamp}"
            print(
                f"{prefix} tid=0x{message.thread_id:x} fac=0x{message.facility:x} "
                f"fmt=0x{message.format_offset:x} {message.text}",
                file=output,
            )
    finally:
        if close_output:
            output.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
