// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#include "common.h"
#include "CommonTypes.h"
#include "CommonMacros.h"
#include "rhassert.h"

//
// Floating point and 64-bit integer math helpers.
//

FCIMPL1_D(uint64_t, RhpDbl2ULng, double val)
{
#if defined(HOST_X86) || defined(HOST_AMD64)
    const double uint64_max_plus_1 = 4294967296.0 * 4294967296.0;
    return (val > 0) ? ((val >= uint64_max_plus_1) ? UINT64_MAX : (uint64_t)val) : 0;
#else
    return (uint64_t)val;
#endif
}
FCIMPLEND

FCIMPL1_D(int64_t, RhpDbl2Lng, double val)
{
#if defined(HOST_X86) || defined(HOST_AMD64) || defined(HOST_ARM)
    const double int64_min = -2147483648.0 * 4294967296.0;
    const double int64_max = 2147483648.0 * 4294967296.0;
    return (val != val) ? 0 : (val <= int64_min) ? INT64_MIN : (val >= int64_max) ? INT64_MAX : (int64_t)val;
#else
    return (int64_t)val;
#endif
}
FCIMPLEND

#ifndef HOST_64BIT
FCIMPL2_LL(int64_t, DivInt64Internal, int64_t i, int64_t j)
{
    ASSERT(j && "Divide by zero!");
    return i / j;
}
FCIMPLEND

FCIMPL2_LL(uint64_t, DivUInt64Internal, uint64_t i, uint64_t j)
{
    ASSERT(j && "Divide by zero!");
    return i / j;
}
FCIMPLEND

FCIMPL2_LL(int64_t, ModInt64Internal, int64_t i, int64_t j)
{
    ASSERT(j && "Divide by zero!");
    return i % j;
}
FCIMPLEND

FCIMPL2_LL(uint64_t, ModUInt64Internal, uint64_t i, uint64_t j)
{
    ASSERT(j && "Divide by zero!");
    return i % j;
}
FCIMPLEND

FCIMPL1_L(double, RhpLng2Dbl, int64_t val)
{
    return (double)val;
}
FCIMPLEND

FCIMPL1_L(double, RhpULng2Dbl, uint64_t val)
{
    return (double)val;
}
FCIMPLEND

FCIMPL1_L(float, RhpLng2Flt, int64_t val)
{
    return (float)val;
}
FCIMPLEND

FCIMPL1_L(float, RhpULng2Flt, uint64_t val)
{
    return (float)val;
}
FCIMPLEND

#endif

#ifndef HOST_64BIT
FCIMPL2(int32_t, DivInt32Internal, int32_t i, int32_t j)
{
    ASSERT(j && "Divide by zero!");
    return i / j;
}
FCIMPLEND

FCIMPL2(uint32_t, DivUInt32Internal, uint32_t i, uint32_t j)
{
    ASSERT(j && "Divide by zero!");
    return i / j;
}
FCIMPLEND

FCIMPL2(int32_t, ModInt32Internal, int32_t i, int32_t j)
{
    ASSERT(j && "Divide by zero!");
    return i % j;
}
FCIMPLEND

FCIMPL2(uint32_t, ModUInt32Internal, uint32_t i, uint32_t j)
{
    ASSERT(j && "Divide by zero!");
    return i % j;
}
FCIMPLEND
#endif

#ifdef HOST_ARM
EXTERN_C int64_t F_CALL_CONV RhpLMul(int64_t i, int64_t j)
{
    return i * j;
}

EXTERN_C uint64_t F_CALL_CONV RhpLRsz(uint64_t i, int32_t j)
{
    return i >> (j & 0x3f);
}

EXTERN_C int64_t F_CALL_CONV RhpLRsh(int64_t i, int32_t j)
{
    return i >> (j & 0x3f);
}

EXTERN_C int64_t F_CALL_CONV RhpLLsh(int64_t i, int32_t j)
{
    return i << (j & 0x3f);
}

#endif // HOST_ARM

#if defined(HOST_X86) || defined(HOST_POWERPC64)

#undef min
#undef max
#include <cmath>

#endif

#ifdef HOST_X86

FCIMPL1_D(double, acos, double x)
    return std::acos(x);
FCIMPLEND

FCIMPL1_F(float, acosf, float x)
    return std::acosf(x);
FCIMPLEND

FCIMPL1_D(double, acosh, double x)
    return std::acosh(x);
FCIMPLEND

FCIMPL1_F(float, acoshf, float x)
    return std::acoshf(x);
FCIMPLEND

FCIMPL1_D(double, asin, double x)
    return std::asin(x);
FCIMPLEND

FCIMPL1_F(float, asinf, float x)
    return std::asinf(x);
FCIMPLEND

FCIMPL1_D(double, asinh, double x)
    return std::asinh(x);
FCIMPLEND

FCIMPL1_F(float, asinhf, float x)
    return std::asinhf(x);
FCIMPLEND

FCIMPL1_D(double, atan, double x)
    return std::atan(x);
FCIMPLEND

FCIMPL1_F(float, atanf, float x)
    return std::atanf(x);
FCIMPLEND

FCIMPL2_DD(double, atan2, double x, double y)
    return std::atan2(x, y);
FCIMPLEND

FCIMPL2_FF(float, atan2f, float x, float y)
    return std::atan2f(x, y);
FCIMPLEND

FCIMPL1_D(double, atanh, double x)
    return std::atanh(x);
FCIMPLEND

FCIMPL1_F(float, atanhf, float x)
    return std::atanhf(x);
FCIMPLEND

FCIMPL1_D(double, cbrt, double x)
    return std::cbrt(x);
FCIMPLEND

FCIMPL1_F(float, cbrtf, float x)
    return std::cbrtf(x);
FCIMPLEND

FCIMPL1_D(double, ceil, double x)
    return std::ceil(x);
FCIMPLEND

FCIMPL1_F(float, ceilf, float x)
    return std::ceilf(x);
FCIMPLEND

FCIMPL1_D(double, cos, double x)
    return std::cos(x);
FCIMPLEND

FCIMPL1_F(float, cosf, float x)
    return std::cosf(x);
FCIMPLEND

FCIMPL1_D(double, cosh, double x)
    return std::cosh(x);
FCIMPLEND

FCIMPL1_F(float, coshf, float x)
    return std::coshf(x);
FCIMPLEND

FCIMPL1_D(double, exp, double x)
    return std::exp(x);
FCIMPLEND

FCIMPL1_F(float, expf, float x)
    return std::expf(x);
FCIMPLEND

FCIMPL1_D(double, floor, double x)
    return std::floor(x);
FCIMPLEND

FCIMPL1_F(float, floorf, float x)
    return std::floorf(x);
FCIMPLEND

FCIMPL1_D(double, log, double x)
    return std::log(x);
FCIMPLEND

FCIMPL1_F(float, logf, float x)
    return std::logf(x);
FCIMPLEND

FCIMPL1_D(double, log2, double x)
    return std::log2(x);
FCIMPLEND

FCIMPL1_F(float, log2f, float x)
    return std::log2f(x);
FCIMPLEND

FCIMPL1_D(double, log10, double x)
    return std::log10(x);
FCIMPLEND

FCIMPL1_F(float, log10f, float x)
    return std::log10f(x);
FCIMPLEND

FCIMPL2_DD(double, pow, double x, double y)
    return std::pow(x, y);
FCIMPLEND

FCIMPL2_FF(float, powf, float x, float y)
    return std::powf(x, y);
FCIMPLEND

FCIMPL1_D(double, sin, double x)
    return std::sin(x);
FCIMPLEND

FCIMPL1_F(float, sinf, float x)
    return std::sinf(x);
FCIMPLEND

FCIMPL1_D(double, sinh, double x)
    return std::sinh(x);
FCIMPLEND

FCIMPL1_F(float, sinhf, float x)
    return std::sinhf(x);
FCIMPLEND

FCIMPL1_D(double, sqrt, double x)
    return std::sqrt(x);
FCIMPLEND

FCIMPL1_F(float, sqrtf, float x)
    return std::sqrtf(x);
FCIMPLEND

FCIMPL1_D(double, tan, double x)
    return std::tan(x);
FCIMPLEND

FCIMPL1_F(float, tanf, float x)
    return std::tanf(x);
FCIMPLEND

FCIMPL1_D(double, tanh, double x)
    return std::tanh(x);
FCIMPLEND

FCIMPL1_F(float, tanhf, float x)
    return std::tanhf(x);
FCIMPLEND

FCIMPL2_DD(double, fmod, double x, double y)
    return std::fmod(x, y);
FCIMPLEND

FCIMPL2_FF(float, fmodf, float x, float y)
    return std::fmodf(x, y);
FCIMPLEND

FCIMPL3_DDD(double, fma, double x, double y, double z)
    return std::fma(x, y, z);
FCIMPLEND

FCIMPL3_FFF(float, fmaf, float x, float y, float z)
    return std::fmaf(x, y, z);
FCIMPLEND

FCIMPL2_DI(double, modf, double x, double* intptr)
    return std::modf(x, intptr);
FCIMPLEND

FCIMPL2_FI(float, modff, float x, float* intptr)
    return std::modff(x, intptr);
FCIMPLEND

#endif

#ifdef HOST_POWERPC64

#define PPC64LE_MATH1_D(_export, _func) \
FCIMPL1_D(double, _export, double x) \
    return ::_func(x); \
FCIMPLEND

#define PPC64LE_MATH1_F(_export, _func) \
FCIMPL1_F(float, _export, float x) \
    return ::_func(x); \
FCIMPLEND

#define PPC64LE_MATH2_DD(_export, _func) \
FCIMPL2_DD(double, _export, double x, double y) \
    return ::_func(x, y); \
FCIMPLEND

#define PPC64LE_MATH2_FF(_export, _func) \
FCIMPL2_FF(float, _export, float x, float y) \
    return ::_func(x, y); \
FCIMPLEND

#define PPC64LE_MATH3_DDD(_export, _func) \
FCIMPL3_DDD(double, _export, double x, double y, double z) \
    return ::_func(x, y, z); \
FCIMPLEND

#define PPC64LE_MATH3_FFF(_export, _func) \
FCIMPL3_FFF(float, _export, float x, float y, float z) \
    return ::_func(x, y, z); \
FCIMPLEND

#define PPC64LE_MATH2_DI(_export, _func) \
FCIMPL2_DI(double, _export, double x, double* intptr) \
    return ::_func(x, intptr); \
FCIMPLEND

#define PPC64LE_MATH2_FI(_export, _func) \
FCIMPL2_FI(float, _export, float x, float* intptr) \
    return ::_func(x, intptr); \
FCIMPLEND

PPC64LE_MATH1_D(RhpPpc64leMathAcos, acos)
PPC64LE_MATH1_F(RhpPpc64leMathAcosF, acosf)
PPC64LE_MATH1_D(RhpPpc64leMathAcosh, acosh)
PPC64LE_MATH1_F(RhpPpc64leMathAcoshF, acoshf)
PPC64LE_MATH1_D(RhpPpc64leMathAsin, asin)
PPC64LE_MATH1_F(RhpPpc64leMathAsinF, asinf)
PPC64LE_MATH1_D(RhpPpc64leMathAsinh, asinh)
PPC64LE_MATH1_F(RhpPpc64leMathAsinhF, asinhf)
PPC64LE_MATH1_D(RhpPpc64leMathAtan, atan)
PPC64LE_MATH1_F(RhpPpc64leMathAtanF, atanf)
PPC64LE_MATH2_DD(RhpPpc64leMathAtan2, atan2)
PPC64LE_MATH2_FF(RhpPpc64leMathAtan2F, atan2f)
PPC64LE_MATH1_D(RhpPpc64leMathAtanh, atanh)
PPC64LE_MATH1_F(RhpPpc64leMathAtanhF, atanhf)
PPC64LE_MATH1_D(RhpPpc64leMathCbrt, cbrt)
PPC64LE_MATH1_F(RhpPpc64leMathCbrtF, cbrtf)
PPC64LE_MATH1_D(RhpPpc64leMathCeil, ceil)
PPC64LE_MATH1_F(RhpPpc64leMathCeilF, ceilf)
PPC64LE_MATH1_D(RhpPpc64leMathCos, cos)
PPC64LE_MATH1_F(RhpPpc64leMathCosF, cosf)
PPC64LE_MATH1_D(RhpPpc64leMathCosh, cosh)
PPC64LE_MATH1_F(RhpPpc64leMathCoshF, coshf)
PPC64LE_MATH1_D(RhpPpc64leMathExp, exp)
PPC64LE_MATH1_F(RhpPpc64leMathExpF, expf)
PPC64LE_MATH1_D(RhpPpc64leMathFloor, floor)
PPC64LE_MATH1_F(RhpPpc64leMathFloorF, floorf)
PPC64LE_MATH1_D(RhpPpc64leMathLog, log)
PPC64LE_MATH1_F(RhpPpc64leMathLogF, logf)
PPC64LE_MATH1_D(RhpPpc64leMathLog2, log2)
PPC64LE_MATH1_F(RhpPpc64leMathLog2F, log2f)
PPC64LE_MATH1_D(RhpPpc64leMathLog10, log10)
PPC64LE_MATH1_F(RhpPpc64leMathLog10F, log10f)
PPC64LE_MATH2_DD(RhpPpc64leMathPow, pow)
PPC64LE_MATH2_FF(RhpPpc64leMathPowF, powf)
PPC64LE_MATH1_D(RhpPpc64leMathSin, sin)
PPC64LE_MATH1_F(RhpPpc64leMathSinF, sinf)
PPC64LE_MATH1_D(RhpPpc64leMathSinh, sinh)
PPC64LE_MATH1_F(RhpPpc64leMathSinhF, sinhf)
PPC64LE_MATH1_D(RhpPpc64leMathSqrt, sqrt)
PPC64LE_MATH1_F(RhpPpc64leMathSqrtF, sqrtf)
PPC64LE_MATH1_D(RhpPpc64leMathTan, tan)
PPC64LE_MATH1_F(RhpPpc64leMathTanF, tanf)
PPC64LE_MATH1_D(RhpPpc64leMathTanh, tanh)
PPC64LE_MATH1_F(RhpPpc64leMathTanhF, tanhf)
PPC64LE_MATH2_DD(RhpPpc64leMathFMod, fmod)
PPC64LE_MATH2_FF(RhpPpc64leMathFModF, fmodf)
PPC64LE_MATH3_DDD(RhpPpc64leMathFma, fma)
PPC64LE_MATH3_FFF(RhpPpc64leMathFmaF, fmaf)
PPC64LE_MATH2_DI(RhpPpc64leMathModF, modf)
PPC64LE_MATH2_FI(RhpPpc64leMathModFF, modff)

#undef PPC64LE_MATH1_D
#undef PPC64LE_MATH1_F
#undef PPC64LE_MATH2_DD
#undef PPC64LE_MATH2_FF
#undef PPC64LE_MATH3_DDD
#undef PPC64LE_MATH3_FFF
#undef PPC64LE_MATH2_DI
#undef PPC64LE_MATH2_FI

#endif
