// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef __HARDWARE_EXCEPTIONS_H__
#define __HARDWARE_EXCEPTIONS_H__

// Initialize hardware exception handling
bool InitializeHardwareExceptionHandling();

#if defined(STRESS_LOG) && defined(TARGET_POWERPC64) && defined(TARGET_UNIX)
void InitializeCurrentThreadHardwareExceptionHandling();
#endif

#endif // __HARDWARE_EXCEPTIONS_H__
