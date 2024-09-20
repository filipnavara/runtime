// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

class JavaInteropNative
{
public:
    static void BeforeGcScanRoots(int condemned, bool is_bgc, bool is_concurrent);
    static void GcScanRoots(ScanFunc* fn, int condemned, int max_gen, ScanContext* sc);
    static void AfterGcScanRoots(_In_ ScanContext* sc);
    static void AfterRestartEE();
    static bool IsTrackedReference(_In_ Object * object);
private:
    static bool m_BridgingInProgress;
    static bool s_BridgeProcessorInitialized;
    static ScanFunc* m_PromoteFunc;
};
