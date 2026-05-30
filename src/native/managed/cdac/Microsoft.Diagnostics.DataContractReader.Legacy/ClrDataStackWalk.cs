// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Microsoft.Diagnostics.DataContractReader.Contracts;
using Microsoft.Diagnostics.DataContractReader.Contracts.StackWalkHelpers;

namespace Microsoft.Diagnostics.DataContractReader.Legacy;

[GeneratedComClass]
public sealed unsafe partial class ClrDataStackWalk : IXCLRDataStackWalk
{
    private readonly TargetPointer _threadAddr;
    private readonly uint _flags;
    private readonly Target _target;
    private readonly IXCLRDataStackWalk? _legacyImpl;

    private bool _currentFrameIsValid;
    private bool _stackSizeSkippedValid;
    private ulong _stackSizeSkipped;
    private readonly IEnumerator<IStackDataFrameHandle> _dataFrames;

    public ClrDataStackWalk(TargetPointer threadAddr, uint flags, Target target, IXCLRDataStackWalk? legacyImpl)
    {
        _threadAddr = threadAddr;
        _flags = flags;
        _target = target;
        _legacyImpl = legacyImpl;

        ThreadData threadData = _target.Contracts.Thread.GetThreadData(_threadAddr);
        _dataFrames = _target.Contracts.StackWalk.CreateStackWalk(threadData).GetEnumerator();

        // IEnumerator<T> begins before the first element.
        // Call MoveNext() to set _dataFrames.Current to the first element.
        _currentFrameIsValid = _dataFrames.MoveNext();
    }

    int IXCLRDataStackWalk.GetContext(uint contextFlags, uint contextBufSize, uint* contextSize, [MarshalUsing(CountElementName = "contextBufSize"), Out] byte[] contextBuf)
    {
        int hr = HResults.S_OK;

        if (_currentFrameIsValid)
        {
            IStackWalk sw = _target.Contracts.StackWalk;
            IStackDataFrameHandle dataFrame = _dataFrames.Current;
            byte[] context = sw.GetRawContext(dataFrame);

            if (contextSize is not null)
            {
                *contextSize = (uint)context.Length;
            }

            if (context.Length > contextBufSize)
            {
                hr = HResults.E_INVALIDARG;
            }
            else if (context.Length > 0)
            {
                Array.Copy(context, 0, contextBuf, 0, context.Length);
            }
        }
        else
        {
            hr = HResults.S_FALSE;
        }


#if DEBUG
        if (_legacyImpl is not null)
        {
            byte[] localContextBuf = new byte[contextBufSize];
            int hrLocal = _legacyImpl.GetContext(contextFlags, contextBufSize, null, localContextBuf);
            Debug.ValidateHResult(hr, hrLocal);

            if (hr == HResults.S_OK)
            {
                IPlatformAgnosticContext contextStruct = IPlatformAgnosticContext.GetContextForPlatform(_target);
                IPlatformAgnosticContext localContextStruct = IPlatformAgnosticContext.GetContextForPlatform(_target);
                contextStruct.FillFromBuffer(contextBuf);
                localContextStruct.FillFromBuffer(localContextBuf);

                Debug.Assert(contextStruct.Equals(localContextStruct));
            }
        }
#endif

        return hr;
    }

    int IXCLRDataStackWalk.GetFrame(DacComNullableByRef<IXCLRDataFrame> frame)
    {
        int hr = HResults.S_OK;

        IXCLRDataFrame? legacyFrame = null;
        if (_legacyImpl is not null)
        {
            DacComNullableByRef<IXCLRDataFrame> legacyFrameOut = new(isNullRef: false);
            int hrLocal = _legacyImpl.GetFrame(legacyFrameOut);
            if (hrLocal < 0)
                return hrLocal;
            legacyFrame = legacyFrameOut.Interface;
        }

        try
        {
            if (!_currentFrameIsValid)
                throw new ArgumentException();

            frame.Interface = new ClrDataFrame(_target, _dataFrames.Current, legacyFrame);
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

        return hr;
    }
    int IXCLRDataStackWalk.GetFrameType(uint* simpleType, uint* detailedType)
    {
        int hr = HResults.S_OK;
        try
        {
            if (!_currentFrameIsValid)
                throw new ArgumentException();

            ClrDataFrame.GetFrameTypes(_target, _dataFrames.Current, simpleType, detailedType);
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
        {
            uint simpleTypeLocal = 0;
            uint detailedTypeLocal = 0;
            int hrLocal = _legacyImpl.GetFrameType(&simpleTypeLocal, &detailedTypeLocal);
            Debug.ValidateHResult(hr, hrLocal, HResultValidationMode.AllowCdacSuccess);
        }
#endif

        return hr;
    }
    int IXCLRDataStackWalk.GetStackSizeSkipped(ulong* stackSizeSkipped)
    {
        if (LegacyFallbackHelper.CanFallback() && _legacyImpl is not null)
        {
            return _legacyImpl.GetStackSizeSkipped(stackSizeSkipped);
        }

        if (!_stackSizeSkippedValid)
        {
            return HResults.S_FALSE;
        }

        if (stackSizeSkipped is not null)
        {
            *stackSizeSkipped = _stackSizeSkipped;
        }

        return HResults.S_OK;
    }

    int IXCLRDataStackWalk.Next()
    {
        TargetPointer previousStackPointer = TargetPointer.Null;
        if (_currentFrameIsValid)
        {
            previousStackPointer = GetStackPointer(_dataFrames.Current);
        }

        int hr;
        try
        {
            _currentFrameIsValid = _dataFrames.MoveNext();
            hr = _currentFrameIsValid ? HResults.S_OK : HResults.S_FALSE;
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

        if (hr == HResults.S_OK)
        {
            TargetPointer currentStackPointer = GetStackPointer(_dataFrames.Current);
            if ((previousStackPointer != TargetPointer.Null) && (currentStackPointer != TargetPointer.Null) &&
                (currentStackPointer.Value >= previousStackPointer.Value))
            {
                _stackSizeSkipped = currentStackPointer.Value - previousStackPointer.Value;
                _stackSizeSkippedValid = true;
            }
            else
            {
                _stackSizeSkipped = 0;
                _stackSizeSkippedValid = false;
            }
        }
        else
        {
            _stackSizeSkipped = 0;
            _stackSizeSkippedValid = false;
        }

        // Advance the legacy stack walk to keep it in sync with the cDAC walk.
        // GetFrame() passes the legacy frame to ClrDataFrame, which delegates
        // GetArgumentByIndex/GetLocalVariableByIndex to it. If we don't advance
        // the legacy walk here, those calls operate on the wrong frame.
        if (_legacyImpl is not null)
        {
            int hrLocal = _legacyImpl.Next();
#if DEBUG
            Debug.ValidateHResult(hr, hrLocal);
#endif
        }

        return hr;
    }

    private TargetPointer GetStackPointer(IStackDataFrameHandle frame)
    {
        IStackWalk sw = _target.Contracts.StackWalk;
        byte[] contextBytes = sw.GetRawContext(frame);
        IPlatformAgnosticContext context = IPlatformAgnosticContext.GetContextForPlatform(_target);
        context.FillFromBuffer(contextBytes);
        return context.StackPointer;
    }

    int IXCLRDataStackWalk.Request(uint reqCode, uint inBufferSize, byte* inBuffer, uint outBufferSize, byte* outBuffer)
    {
        const uint DACSTACKPRIV_REQUEST_FRAME_DATA = 0xf0000000;

        int hr = HResults.S_OK;

        switch (reqCode)
        {
            case DACSTACKPRIV_REQUEST_FRAME_DATA:
                if ((inBufferSize != 0) || (inBuffer is not null) || (outBufferSize != sizeof(ulong)))
                {
                    hr = HResults.E_INVALIDARG;
                }
                else if (!_currentFrameIsValid)
                {
                    hr = HResults.E_INVALIDARG;
                }
                else
                {
                    IStackWalk sw = _target.Contracts.StackWalk;
                    IStackDataFrameHandle frameData = _dataFrames.Current;
                    TargetPointer frameAddr = sw.GetFrameAddress(frameData);
                    *(ulong*)outBuffer = frameAddr.ToClrDataAddress(_target);
                    hr = HResults.S_OK;
                }
                break;
            default:
                hr = HResults.E_INVALIDARG;
                break;
        }

#if DEBUG
        if (_legacyImpl is not null)
        {
            int hrLocal;
            byte[] localOutBuffer = new byte[outBufferSize];
            fixed (byte* localOutBufferPtr = localOutBuffer)
            {
                hrLocal = _legacyImpl.Request(reqCode, inBufferSize, inBuffer, outBufferSize, localOutBufferPtr);
            }
            Debug.ValidateHResult(hr, hrLocal);

            for (int i = 0; i < outBufferSize; i++)
            {
                Debug.Assert(localOutBuffer[i] == outBuffer[i], $"cDAC: {outBuffer[i]:x}, DAC: {localOutBuffer[i]:x}");
            }
        }
#endif
        return hr;
    }
    int IXCLRDataStackWalk.SetContext(uint contextSize, [In, MarshalUsing(CountElementName = "contextSize")] byte[] context)
        => LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.SetContext(contextSize, context) : HResults.E_NOTIMPL;
    int IXCLRDataStackWalk.SetContext2(uint flags, uint contextSize, [In, MarshalUsing(CountElementName = "contextSize")] byte[] context)
        => LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.SetContext2(flags, contextSize, context) : HResults.E_NOTIMPL;
}
