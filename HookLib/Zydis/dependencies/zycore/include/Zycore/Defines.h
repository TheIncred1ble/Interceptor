/***************************************************************************************************

  Zyan Core Library (Zycore-C)

  Original Author : Florian Bernd, Joel Hoener

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.

***************************************************************************************************/

/**
 * @file
 * @brief   General helper and platform detection macros.
 */

#ifndef ZYCORE_DEFINES_H
#define ZYCORE_DEFINES_H

/* ============================================================================================== */
/* Meta macros                                                                                    */
/* ============================================================================================== */

/**
 * @brief   Concatenates two values using the stringify operator (`##`).
 *
 * @brief   x   The first value.
 * @brief   y   The second value.
 *
 * @return  The combined string of the given values.
 */
#define ZYAN_MACRO_CONCAT(x, y) x ## y

/**
 * @brief   Concatenates two values using the stringify operator (`##`) and expands the value to
 *          be used in another macro.
 *
 * @brief   x   The first value.
 * @brief   y   The second value.
 *
 * @return  The combined string of the given values.
 */
#define ZYAN_MACRO_CONCAT_EXPAND(x, y) ZYAN_MACRO_CONCAT(x, y)

/* ============================================================================================== */
/* Compiler detection                                                                             */
/* ============================================================================================== */

#if defined(__clang__)
#   define ZYAN_CLANG
#   define ZYAN_GNUC
#elif defined(__ICC) || defined(__INTEL_COMPILER)
#   define ZYAN_ICC
#elif defined(__GNUC__) || defined(__GNUG__)
#   define ZYAN_GCC
#   define ZYAN_GNUC
#elif defined(_MSC_VER)
#   define ZYAN_MSVC
#elif defined(__BORLANDC__)
#   define ZYAN_BORLAND
#else
#   define ZYAN_UNKNOWN_COMPILER
#endif

/* ============================================================================================== */
/* Platform detection                                                                             */
/* ============================================================================================== */

#if defined(_WIN32)
#   define ZYAN_WINDOWS
#elif defined(__EMSCRIPTEN__)
#   define ZYAN_EMSCRIPTEN
#elif defined(__APPLE__)
#   define ZYAN_APPLE
#   define ZYAN_POSIX
#elif defined(__linux)
#   define ZYAN_LINUX
#   define ZYAN_POSIX
#elif defined(__unix)
#   define ZYAN_UNIX
#   define ZYAN_POSIX
#elif defined(__posix)
#   define ZYAN_POSIX
#else
#   define ZYAN_UNKNOWN_PLATFORM
#endif

/* ============================================================================================== */
/* Kernel mode detection                                                                          */
/* ============================================================================================== */

#if (defined(ZYAN_WINDOWS) && defined(_KERNEL_MODE)) || \
    (defined(ZYAN_APPLE) && defined(KERNEL)) || \
    (defined(ZYAN_LINUX) && defined(__KERNEL__)) || \
    (defined(__FreeBSD_kernel__))
#   define ZYAN_KERNEL
#else
#   define ZYAN_USER
#endif

/* ============================================================================================== */
/* Architecture detection                                                                         */
/* ============================================================================================== */

#if defined(_M_AMD64) || defined(__x86_64__)
#   define ZYAN_X64
#elif defined(_M_IX86) || defined(__i386__)
#   define ZYAN_X86
#elif defined(_M_ARM64) || defined(__aarch64__)
#   define ZYAN_AARCH64
#elif defined(_M_ARM) || defined(_M_ARMT) || defined(__arm__) || defined(__thumb__)
#   define ZYAN_ARM
#elif defined(__EMSCRIPTEN__)
    // Nothing to do, `ZYAN_EMSCRIPTEN` is both platform and arch macro for this one.
#else
#   error "Unsupported architecture detected"
#endif

/* ============================================================================================== */
/* Debug/Release detection                                                                        */
/* ============================================================================================== */

#if defined(ZYAN_MSVC) || defined(ZYAN_BORLAND)
#   ifdef _DEBUG
#       define ZYAN_DEBUG
#   else
#       define ZYAN_RELEASE
#   endif
#elif defined(ZYAN_GNUC) || defined(ZYAN_ICC)
#   ifdef NDEBUG
#       define ZYAN_RELEASE
#   else
#       define ZYAN_DEBUG
#   endif
#else
#   define ZYAN_RELEASE
#endif

/* ============================================================================================== */
/* Misc compatibility macros                                                                      */
/* ============================================================================================== */

#if defined(ZYAN_MSVC) || defined(ZYAN_BORLAND)
#   define ZYAN_INLINE __inline
#else
#   define ZYAN_INLINE static inline
#endif

/* ============================================================================================== */
/* Debugging and optimization macros                                                              */
/* ============================================================================================== */

/**
 * @brief   Runtime debug assersion.
 */
#if defined(ZYAN_NO_LIBC)
#   define ZYAN_ASSERT(condition) (void)(condition)
#elif defined(ZYAN_WINDOWS) && defined(ZYAN_KERNEL)
#   include <wdm.h>
#   define ZYAN_ASSERT(condition) NT_ASSERT(condition)
#else
#   include <assert.h>
#   define ZYAN_ASSERT(condition) assert(condition)
#endif

/**
 * @brief   Compiler-time assertion.
 */
#if __STDC_VERSION__ >= 201112L
#   define ZYAN_STATIC_ASSERT(x) _Static_assert(x, #x)
#else
#   define ZYAN_STATIC_ASSERT(x) \
        typedef int ZYAN_MACRO_CONCAT_EXPAND(ZYAN_SASSERT_, __COUNTER__) [(x) ? 1 : -1]
#endif

/**
 * @brief	Marks the current code path as unreachable.
 */
#if defined(ZYAN_RELEASE)
#   if defined(ZYAN_CLANG) // GCC eagerly evals && RHS, we have to use nested ifs.
#       if __has_builtin(__builtin_unreachable)
#           define ZYAN_UNREACHABLE __builtin_unreachable()
#       else
#           define ZYAN_UNREACHABLE for(;;)
#       endif
#   elif defined(ZYAN_GCC) && ((__GNUC__ == 4 && __GNUC_MINOR__ > 4) || __GNUC__ > 4)
#       define ZYAN_UNREACHABLE __builtin_unreachable()
#   elif defined(ZYAN_ICC)
#       ifdef ZYAN_WINDOWS
#           include <stdlib.h> // "missing return statement" workaround
#           define ZYAN_UNREACHABLE __assume(0); (void)abort()
#       else
#           define ZYAN_UNREACHABLE __builtin_unreachable()
#       endif
#   elif defined(ZYAN_MSVC)
#       define ZYAN_UNREACHABLE __assume(0)
#   else
#       define ZYAN_UNREACHABLE for(;;)
#   endif
#elif defined(ZYAN_NO_LIBC)
#   define ZYAN_UNREACHABLE for(;;)
#elif defined(ZYAN_WINDOWS) && defined(ZYAN_KERNEL)
#   define ZYAN_UNREACHABLE { __fastfail(0); for(;;){} }
#else
#   include <stdlib.h>
#   define ZYAN_UNREACHABLE { assert(0); abort(); }
#endif

/* ============================================================================================== */
/* Utils                                                                                          */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* General purpose                                                                                */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Marks the specified parameter as unused.
 *
 * @param   x   The name of the unused parameter.
 */
#define ZYAN_UNUSED(x) (void)(x)

/**
 * @brief   Intentional fallthrough.
 */
#if defined(ZYAN_GCC) && __GNUC__ > 7
#   define ZYAN_FALLTHROUGH __attribute__ ((fallthrough))
#else
#   define ZYAN_FALLTHROUGH
#endif

/**
 * @brief   Declares a bitfield.
 *
 * @param   x   The size (in bits) of the bitfield.
 */
#define ZYAN_BITFIELD(x) : x

/**
 * @brief   Marks functions that require libc (cannot be used with `ZYAN_NO_LIBC`).
 */
#define ZYAN_REQUIRES_LIBC

/**
 * @brief   Decorator for `printf`-style functions.
 *
 * @param   format_index    The 1-based index of the format string parameter.
 * @param   first_to_check  The 1-based index of the format arguments parameter.
 */
#if defined(__RESHARPER__)
#   define ZYAN_PRINTF_ATTR(format_index, first_to_check) \
        [[gnu::format(printf, format_index, first_to_check)]]
#elif defined(ZYAN_GCC)
#   define ZYAN_PRINTF_ATTR(format_index, first_to_check) \
        __attribute__((format(printf, format_index, first_to_check)))
#else
#   define ZYAN_PRINTF_ATTR(format_index, first_to_check)
#endif

/**
 * @brief   Decorator for `wprintf`-style functions.
 *
 * @param   format_index    The 1-based index of the format string parameter.
 * @param   first_to_check  The 1-based index of the format arguments parameter.
 */
#if defined(__RESHARPER__)
#   define ZYAN_WPRINTF_ATTR(format_index, first_to_check) \
        [[rscpp::format(wprintf, format_index, first_to_check)]]
#else
#   define ZYAN_WPRINTF_ATTR(format_index, first_to_check)
#endif

/* ---------------------------------------------------------------------------------------------- */
/* Arrays                                                                                         */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Returns the length (number of elements) of an array.
 *
 * @param   a   The name of the array.
 *
 * @return  The number of elements of the given array.
 */
#define ZYAN_ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))

/* ---------------------------------------------------------------------------------------------- */
/* Arithmetic                                                                                     */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Returns the smaller value of `a` or `b`.
 *
 * @param   a   The first value.
 * @param   b   The second value.
 *
 * @return  The smaller value of `a` or `b`.
 */
#define ZYAN_MIN(a, b) (((a) < (b)) ? (a) : (b))

/**
 * @brief   Returns the bigger value of `a` or `b`.
 *
 * @param   a   The first value.
 * @param   b   The second value.
 *
 * @return  The bigger value of `a` or `b`.
 */
#define ZYAN_MAX(a, b) (((a) > (b)) ? (a) : (b))

/**
 * @brief   Returns the absolute value of `a`.
 *
 * @param   a   The value.
 *
 * @return  The absolute value of `a`.
 */
#define ZYAN_ABS(a) (((a) < 0) ? -(a) : (a))

/**
 * @brief   Checks, if the given value is a power of 2.
 *
 * @param   x   The value.
 *
 * @return  `ZYAN_TRUE`, if the given value is a power of 2 or `ZYAN_FALSE`, if not.
 *
 * Note that this macro always returns `ZYAN_TRUE` for `x == 0`.
 */
#define ZYAN_IS_POWER_OF_2(x) (((x) & ((x) - 1)) == 0)

/**
 * @brief   Aligns the value to the nearest given alignment boundary (by rounding it up).
 *
 * @param   x       The value.
 * @param   align   The desired alignment.
 *
 * @return  The aligned value.
 *
 * Note that this macro only works for powers of 2.
 */
#define ZYAN_ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))

/**
 * @brief   Aligns the value to the nearest given alignment boundary (by rounding it down).
 *
 * @param   x       The value.
 * @param   align   The desired alignment.
 *
 * @return  The aligned value.
 *
 * Note that this macro only works for powers of 2.
 */
#define ZYAN_ALIGN_DOWN(x, align) (((x) - 1) & ~((align) - 1))

/* ---------------------------------------------------------------------------------------------- */
/* Bit operations                                                                                 */
/* ---------------------------------------------------------------------------------------------- */

/*
 * @brief   Checks, if the bit at index `b` is required to present the ordinal value `n`.
 *
 * @param   n   The ordinal value.
 * @param   b   The bit index.
 *
 * @return  `ZYAN_TRUE`, if the bit at index `b` is required to present the ordinal value `n` or
 *          `ZYAN_FALSE`, if not.
 *
 * Note that this macro always returns `ZYAN_FALSE` for `n == 0`.
 */
#define ZYAN_NEEDS_BIT(n, b) (((unsigned long)(n) >> (b)) > 0)

/*
 * @brief   Returns the number of bits required to represent the ordinal value `n`.
 *
 * @param   n   The ordinal value.
 *
 * @return  The number of bits required to represent the ordinal value `n`.
 *
 * Note that this macro returns `0` for `n == 0`.
 */
#define ZYAN_BITS_TO_REPRESENT(n) \
    ( \
        ZYAN_NEEDS_BIT(n,  0) + ZYAN_NEEDS_BIT(n,  1) + \
        ZYAN_NEEDS_BIT(n,  2) + ZYAN_NEEDS_BIT(n,  3) + \
        ZYAN_NEEDS_BIT(n,  4) + ZYAN_NEEDS_BIT(n,  5) + \
        ZYAN_NEEDS_BIT(n,  6) + ZYAN_NEEDS_BIT(n,  7) + \
        ZYAN_NEEDS_BIT(n,  8) + ZYAN_NEEDS_BIT(n,  9) + \
        ZYAN_NEEDS_BIT(n, 10) + ZYAN_NEEDS_BIT(n, 11) + \
        ZYAN_NEEDS_BIT(n, 12) + ZYAN_NEEDS_BIT(n, 13) + \
        ZYAN_NEEDS_BIT(n, 14) + ZYAN_NEEDS_BIT(n, 15) + \
        ZYAN_NEEDS_BIT(n, 16) + ZYAN_NEEDS_BIT(n, 17) + \
        ZYAN_NEEDS_BIT(n, 18) + ZYAN_NEEDS_BIT(n, 19) + \
        ZYAN_NEEDS_BIT(n, 20) + ZYAN_NEEDS_BIT(n, 21) + \
        ZYAN_NEEDS_BIT(n, 22) + ZYAN_NEEDS_BIT(n, 23) + \
        ZYAN_NEEDS_BIT(n, 24) + ZYAN_NEEDS_BIT(n, 25) + \
        ZYAN_NEEDS_BIT(n, 26) + ZYAN_NEEDS_BIT(n, 27) + \
        ZYAN_NEEDS_BIT(n, 28) + ZYAN_NEEDS_BIT(n, 29) + \
        ZYAN_NEEDS_BIT(n, 30) + ZYAN_NEEDS_BIT(n, 31)   \
    )

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */

#endif /* ZYCORE_DEFINES_H */
