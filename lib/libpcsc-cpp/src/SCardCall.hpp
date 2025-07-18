/*
 * Copyright (c) 2020-2024 Estonian Information System Authority
 *
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
 */

#pragma once

#include "pcsc-cpp/pcsc-cpp.hpp"
#include "pcsc-cpp/comp_winscard.hpp"
#include "pcsc-cpp/pcsc-cpp-utils.hpp"

#include <string>

#ifdef _WIN32
#include <winerror.h>
#endif // _WIN32

namespace pcsc_cpp
{

template <auto Func, typename... Args>
inline void SCardCall(const char* callerFunctionName, const char* file, int line,
                      const char* scardFunctionName, Args&&... args)
{
    const LONG result = Func(std::forward<Args>(args)...);
    auto buildErrorMessage = [&] {
        return std::string(scardFunctionName) + " returned " + int2hexstr(result) + " in "
            + removeAbsolutePathPrefix(file) + ':' + std::to_string(line) + ':'
            + callerFunctionName;
    };

    switch (result) {
    case SCARD_S_SUCCESS:
        return;
    case LONG(SCARD_E_NO_SERVICE):
    case LONG(SCARD_E_SERVICE_STOPPED):
        throw ScardServiceNotRunningError(buildErrorMessage());
    case LONG(SCARD_E_NO_READERS_AVAILABLE):
    case LONG(SCARD_E_READER_UNAVAILABLE):
        throw ScardNoReadersError(buildErrorMessage());
    case LONG(SCARD_E_NO_SMARTCARD):
#ifdef _WIN32
    case ERROR_NO_MEDIA_IN_DRIVE:
#endif // _WIN32
        throw ScardNoCardError(buildErrorMessage());
    case LONG(SCARD_E_NOT_READY):
    case LONG(SCARD_E_INVALID_VALUE):
    case LONG(SCARD_E_COMM_DATA_LOST):
    case LONG(SCARD_W_RESET_CARD):
#ifdef _WIN32
    case ERROR_IO_DEVICE:
#endif // _WIN32
        throw ScardCardCommunicationFailedError(buildErrorMessage());
    case LONG(SCARD_W_REMOVED_CARD):
        throw ScardCardRemovedError(buildErrorMessage());
    case LONG(SCARD_E_NOT_TRANSACTED):
        throw ScardTransactionFailedError(buildErrorMessage());
    default:
        throw ScardError(buildErrorMessage());
    }
}

} // namespace pcsc_cpp

#define SCard(APIFunctionName, ...)                                                                \
    SCardCall<SCard##APIFunctionName>(__FUNCTION__, __FILE__, __LINE__, "SCard" #APIFunctionName,  \
                                      __VA_ARGS__)
