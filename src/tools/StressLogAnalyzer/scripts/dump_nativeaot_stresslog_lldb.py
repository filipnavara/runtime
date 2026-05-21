# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.

"""LLDB command for dumping NativeAOT StressLog chunks.

Usage from lldb:

    command script import src/tools/StressLogAnalyzer/scripts/dump_nativeaot_stresslog_lldb.py
    dump_nativeaot_stresslog /tmp/stresslog-capture

The command writes stresslog-map.txt plus one binary file per StressLogChunk.
Decode the directory with decode_nativeaot_stresslog.py.
"""

from __future__ import annotations

import os
import shlex

import lldb


def __lldb_init_module(debugger, internal_dict) -> None:  # noqa: D401
    del internal_dict
    debugger.HandleCommand(
        "command script add -f dump_nativeaot_stresslog_lldb.dump_nativeaot_stresslog dump_nativeaot_stresslog"
    )


def _eval_uint(frame: lldb.SBFrame, expression: str) -> int:
    value = frame.EvaluateExpression(expression)
    if not value.IsValid() or value.GetError().Fail():
        error = value.GetError().GetCString() if value.GetError().Fail() else "invalid expression"
        raise RuntimeError(f"failed to evaluate {expression!r}: {error}")
    return int(value.GetValueAsUnsigned())


def _field_offset(sbtype: lldb.SBType, name: str) -> int:
    for i in range(sbtype.GetNumberOfFields()):
        field = sbtype.GetFieldAtIndex(i)
        if field.GetName() == name:
            return field.GetOffsetInBytes()
    raise RuntimeError(f"type {sbtype.GetName()} has no field named {name}")


def _read_uint(data: bytes, offset: int, size: int) -> int:
    return int.from_bytes(data[offset : offset + size], "little", signed=False)


def _read_field(data: bytes, offsets: dict[str, int], name: str, size: int) -> int:
    return _read_uint(data, offsets[name], size)


def _safe_name_for_addr(addr: int) -> str:
    return f"0x{addr:016x}"


def _read_memory(process: lldb.SBProcess, address: int, size: int) -> bytes:
    error = lldb.SBError()
    data = process.ReadMemory(address, size, error)
    if error.Fail():
        raise RuntimeError(f"failed to read memory at 0x{address:x}: {error.GetCString()}")
    return bytes(data)


def dump_nativeaot_stresslog(debugger, command, result, internal_dict) -> None:
    del internal_dict
    args = shlex.split(command)
    if len(args) != 1:
        result.SetError("usage: dump_nativeaot_stresslog <output-directory>")
        return

    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()
    out_dir = args[0]
    os.makedirs(out_dir, exist_ok=True)

    try:
        pointer_size = target.GetAddressByteSize()

        log_type = target.FindFirstType("StressLog")
        thread_type = target.FindFirstType("ThreadStressLog")
        chunk_type = target.FindFirstType("StressLogChunk")
        if not log_type.IsValid() or not thread_type.IsValid() or not chunk_type.IsValid():
            raise RuntimeError("StressLog, ThreadStressLog, or StressLogChunk debug type is unavailable")

        log_offsets = {
            name: _field_offset(log_type, name)
            for name in (
                "facilitiesToLog",
                "levelToLog",
                "MaxSizePerThread",
                "MaxSizeTotal",
                "totalChunk",
                "logs",
                "tickFrequency",
                "startTimeStamp",
                "moduleOffset",
            )
        }
        thread_offsets = {
            name: _field_offset(thread_type, name)
            for name in (
                "next",
                "threadId",
                "isDead",
                "writeHasWrapped",
                "curPtr",
                "chunkListHead",
                "chunkListTail",
                "curWriteChunk",
                "chunkListLength",
                "pThread",
            )
        }
        chunk_offsets = {name: _field_offset(chunk_type, name) for name in ("prev", "next")}

        chunk_size = chunk_type.GetByteSize()
        if chunk_size == 0:
            chunk_size = _eval_uint(frame, "sizeof(StressLogChunk)")

        log_addr = _eval_uint(frame, "(uintptr_t)&StressLog::theLog")
        log_data = _read_memory(process, log_addr, log_type.GetByteSize())
        module_offset = _read_field(log_data, log_offsets, "moduleOffset", pointer_size)
        logs = _read_field(log_data, log_offsets, "logs", pointer_size)

        map_path = os.path.join(out_dir, "stresslog-map.txt")
        with open(map_path, "w", encoding="utf-8") as map_file:
            map_file.write(f"stresslog=0x{log_addr:x}\n")
            map_file.write(f"moduleOffset=0x{module_offset:x}\n")
            map_file.write(f"facilities=0x{_read_field(log_data, log_offsets, 'facilitiesToLog', 4):x}\n")
            map_file.write(f"level={_read_field(log_data, log_offsets, 'levelToLog', 4)}\n")
            map_file.write(f"maxPerThread={_read_field(log_data, log_offsets, 'MaxSizePerThread', 4)}\n")
            map_file.write(f"maxTotal={_read_field(log_data, log_offsets, 'MaxSizeTotal', 4)}\n")
            map_file.write(f"totalChunk={_read_field(log_data, log_offsets, 'totalChunk', 4)}\n")
            map_file.write(f"logs=0x{logs:x}\n")
            map_file.write(f"tickFrequency={_read_field(log_data, log_offsets, 'tickFrequency', 8)}\n")
            map_file.write(f"startTimeStamp={_read_field(log_data, log_offsets, 'startTimeStamp', 8)}\n")
            map_file.write(f"chunkStructSize={chunk_size}\n")

            thread_log = logs
            thread_index = 0
            while thread_log != 0 and thread_index < 1024:
                thread_data = _read_memory(process, thread_log, thread_type.GetByteSize())
                map_file.write(f"\nthread[{thread_index}] addr=0x{thread_log:x}\n")
                map_file.write(f"  threadId=0x{_read_field(thread_data, thread_offsets, 'threadId', 8):x}\n")
                map_file.write(f"  isDead={_read_field(thread_data, thread_offsets, 'isDead', 1)}\n")
                map_file.write(f"  writeHasWrapped={_read_field(thread_data, thread_offsets, 'writeHasWrapped', 1)}\n")
                map_file.write(f"  curPtr=0x{_read_field(thread_data, thread_offsets, 'curPtr', pointer_size):x}\n")
                map_file.write(f"  chunkListHead=0x{_read_field(thread_data, thread_offsets, 'chunkListHead', pointer_size):x}\n")
                map_file.write(f"  chunkListTail=0x{_read_field(thread_data, thread_offsets, 'chunkListTail', pointer_size):x}\n")
                map_file.write(f"  curWriteChunk=0x{_read_field(thread_data, thread_offsets, 'curWriteChunk', pointer_size):x}\n")
                map_file.write(f"  chunkListLength={_read_field(thread_data, thread_offsets, 'chunkListLength', pointer_size)}\n")
                map_file.write(f"  pThread=0x{_read_field(thread_data, thread_offsets, 'pThread', pointer_size):x}\n")

                head = _read_field(thread_data, thread_offsets, "chunkListHead", pointer_size)
                chunk = head
                chunk_index = 0
                seen: set[int] = set()
                while chunk != 0 and chunk_index < 4096 and chunk not in seen:
                    seen.add(chunk)
                    chunk_data = _read_memory(process, chunk, chunk_size)
                    prev_chunk = _read_field(chunk_data, chunk_offsets, "prev", pointer_size)
                    next_chunk = _read_field(chunk_data, chunk_offsets, "next", pointer_size)
                    chunk_name = f"thread-{thread_index:02d}-chunk-{chunk_index:04d}-{_safe_name_for_addr(chunk)}.bin"
                    chunk_path = os.path.join(out_dir, chunk_name)
                    with open(chunk_path, "wb") as chunk_file:
                        chunk_file.write(chunk_data)
                    map_file.write(
                        f"  chunk[{chunk_index}] addr=0x{chunk:x} "
                        f"prev=0x{prev_chunk:x} next=0x{next_chunk:x} file={chunk_name}\n"
                    )
                    chunk_index += 1
                    chunk = next_chunk
                    if chunk == head:
                        break

                thread_log = _read_field(thread_data, thread_offsets, "next", pointer_size)
                thread_index += 1

        result.PutCString(f"Wrote NativeAOT stresslog capture to {out_dir}")
    except Exception as ex:  # noqa: BLE001
        result.SetError(str(ex))
