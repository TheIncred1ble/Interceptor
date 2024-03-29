/***************************************************************************************************

  Zyan Core Library (Zycore-C)

  Original Author : Florian Bernd

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
 * @brief
 */

#ifndef ZYCORE_SYNCHRONIZATION_H
#define ZYCORE_SYNCHRONIZATION_H

#include <ZycoreExportConfig.h>
#include <Zycore/Defines.h>
#include <Zycore/Status.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================================== */
/* Enums and types                                                                                */
/* ============================================================================================== */

#if   defined(ZYAN_POSIX)

#include <pthread.h>

/* ---------------------------------------------------------------------------------------------- */
/* General                                                                                        */
/* ---------------------------------------------------------------------------------------------- */

typedef pthread_mutex_t ZyanCriticalSection;

/* ---------------------------------------------------------------------------------------------- */

#elif defined(ZYAN_WINDOWS)

#include <Windows.h>

/* ---------------------------------------------------------------------------------------------- */
/* General                                                                                        */
/* ---------------------------------------------------------------------------------------------- */

typedef CRITICAL_SECTION ZyanCriticalSection;

/* ---------------------------------------------------------------------------------------------- */

#else
#   error "Unsupported platform detected"
#endif

/* ============================================================================================== */
/* Exported functions                                                                             */
/* ============================================================================================== */

/* ---------------------------------------------------------------------------------------------- */
/* Critical Section                                                                               */
/* ---------------------------------------------------------------------------------------------- */

/**
 * @brief   Initializes a critical section.
 *
 * @param   critical_section    A pointer to the `ZyanCriticalSection` struct.
 */
ZYCORE_EXPORT void ZyanCriticalSectionInitialize(ZyanCriticalSection* critical_section);

/**
 * @brief   Enters a critical section.
 *
 * @param   critical_section    A pointer to the `ZyanCriticalSection` struct.
 */
ZYCORE_EXPORT void ZyanCriticalSectionEnter(ZyanCriticalSection* critical_section);

/**
 * @brief   Tries to enter a critical section.
 *
 * @param   critical_section    A pointer to the `ZyanCriticalSection` struct.
 *
 * @return  Returns `ZYAN_TRUE` if the critical section was successfully entered or `ZYAN_FALSE`,
 *          if not.
 */
ZYCORE_EXPORT ZyanBool ZyanCriticalSectionTryEnter(ZyanCriticalSection* critical_section);

/**
 * @brief   Leaves a critical section.
 *
 * @param   critical_section    A pointer to the `ZyanCriticalSection` struct.
 */
ZYCORE_EXPORT void ZyanCriticalSectionLeave(ZyanCriticalSection* critical_section);

/**
 * @brief   Deletes a critical section.
 *
 * @param   critical_section    A pointer to the `ZyanCriticalSection` struct.
 */
ZYCORE_EXPORT void ZyanCriticalSectionDelete(ZyanCriticalSection* critical_section);

/* ---------------------------------------------------------------------------------------------- */

/* ============================================================================================== */

#ifdef __cplusplus
}
#endif

#endif /* ZYCORE_SYNCHRONIZATION_H */
