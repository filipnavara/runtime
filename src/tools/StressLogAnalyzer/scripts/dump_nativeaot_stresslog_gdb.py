# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.

"""GDB command for dumping NativeAOT StressLog chunks.

Usage from gdb:

    source src/tools/StressLogAnalyzer/scripts/dump_nativeaot_stresslog_gdb.py
    dump_nativeaot_stresslog /tmp/stresslog-capture

The command writes stresslog-map.txt plus one binary file per StressLogChunk.
Decode the directory with decode_nativeaot_stresslog.py.
"""

from __future__ import annotations

import os

import gdb


def _int(value: gdb.Value) -> int:
    return int(value)


def _ptr(value: gdb.Value) -> int:
    if int(value) == 0:
        return 0
    return int(value)


def _field(value: gdb.Value, name: str) -> gdb.Value:
    return value.dereference()[name]


def _safe_name_for_addr(addr: int) -> str:
    return f"0x{addr:016x}"


class DumpNativeAotStressLog(gdb.Command):
    """Dump NativeAOT StressLog chunks to a directory."""

    def __init__(self) -> None:
        super().__init__("dump_nativeaot_stresslog", gdb.COMMAND_DATA)

    def invoke(self, arg: str, from_tty: bool) -> None:
        del from_tty
        out_dir = arg.strip()
        if not out_dir:
            raise gdb.GdbError("usage: dump_nativeaot_stresslog <output-directory>")

        os.makedirs(out_dir, exist_ok=True)

        log = gdb.parse_and_eval("StressLog::theLog")
        log_addr = _ptr(gdb.parse_and_eval("&StressLog::theLog"))
        chunk_size = int(gdb.lookup_type("StressLogChunk").sizeof)

        map_path = os.path.join(out_dir, "stresslog-map.txt")
        with open(map_path, "w", encoding="utf-8") as map_file:
            map_file.write(f"stresslog=0x{log_addr:x}\n")
            map_file.write(f"moduleOffset=0x{_int(log['moduleOffset']):x}\n")
            map_file.write(f"facilities=0x{_int(log['facilitiesToLog']):x}\n")
            map_file.write(f"level={_int(log['levelToLog'])}\n")
            map_file.write(f"maxPerThread={_int(log['MaxSizePerThread'])}\n")
            map_file.write(f"maxTotal={_int(log['MaxSizeTotal'])}\n")
            map_file.write(f"totalChunk={_int(log['totalChunk'])}\n")
            map_file.write(f"logs=0x{_ptr(log['logs']):x}\n")
            map_file.write(f"tickFrequency={_int(log['tickFrequency'])}\n")
            map_file.write(f"startTimeStamp={_int(log['startTimeStamp'])}\n")
            map_file.write(f"chunkStructSize={chunk_size}\n")

            thread = log["logs"]
            thread_index = 0
            while _ptr(thread) != 0 and thread_index < 1024:
                thread_addr = _ptr(thread)
                t = thread.dereference()
                map_file.write(f"\nthread[{thread_index}] addr=0x{thread_addr:x}\n")
                map_file.write(f"  threadId=0x{_int(t['threadId']):x}\n")
                map_file.write(f"  isDead={1 if bool(t['isDead']) else 0}\n")
                map_file.write(f"  writeHasWrapped={1 if bool(t['writeHasWrapped']) else 0}\n")
                map_file.write(f"  curPtr=0x{_ptr(t['curPtr']):x}\n")
                map_file.write(f"  chunkListHead=0x{_ptr(t['chunkListHead']):x}\n")
                map_file.write(f"  chunkListTail=0x{_ptr(t['chunkListTail']):x}\n")
                map_file.write(f"  curWriteChunk=0x{_ptr(t['curWriteChunk']):x}\n")
                map_file.write(f"  chunkListLength={_int(t['chunkListLength'])}\n")
                map_file.write(f"  pThread=0x{_ptr(t['pThread']):x}\n")

                head = t["chunkListHead"]
                chunk = head
                chunk_index = 0
                seen: set[int] = set()
                while _ptr(chunk) != 0 and chunk_index < 4096:
                    chunk_addr = _ptr(chunk)
                    if chunk_addr in seen:
                        break
                    seen.add(chunk_addr)

                    chunk_name = f"thread-{thread_index:02d}-chunk-{chunk_index:04d}-{_safe_name_for_addr(chunk_addr)}.bin"
                    chunk_path = os.path.join(out_dir, chunk_name)
                    start = chunk_addr
                    end = chunk_addr + chunk_size
                    gdb.execute(f"dump binary memory {chunk_path} 0x{start:x} 0x{end:x}", to_string=True)

                    c = chunk.dereference()
                    map_file.write(
                        f"  chunk[{chunk_index}] addr=0x{chunk_addr:x} "
                        f"prev=0x{_ptr(c['prev']):x} next=0x{_ptr(c['next']):x} file={chunk_name}\n"
                    )

                    chunk_index += 1
                    chunk = c["next"]
                    if _ptr(chunk) == _ptr(head):
                        break

                thread_index += 1
                thread = t["next"]

        gdb.write(f"Wrote NativeAOT stresslog capture to {out_dir}\n")


DumpNativeAotStressLog()
