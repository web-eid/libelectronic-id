/*
 * Copyright (c) 2020-2023 Estonian Information System Authority
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

#include <pcsc-mock/pcsc-mock.hpp>

#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
using LPSCARD_READERSTATE = SCARD_READERSTATE*;
#define MOCK_CONST
#else
#include <winscard.h>
#define MOCK_CONST const
#endif

#include <iostream>
#include <cstring>

#include <sstream>
#include <iomanip>

using namespace std::string_literals;

namespace
{

inline std::string bytes2hexstr(const PcscMock::byte_vector& bytes)
{
    std::ostringstream hexStringBuilder;

    hexStringBuilder << std::setfill('0') << std::hex;

    for (const auto byte : bytes)
        hexStringBuilder << std::setw(2) << short(byte);

    return hexStringBuilder.str();
}

} // namespace

PcscMock::byte_vector PcscMock::responseForApduCommand(const PcscMock::byte_vector& command)
{
    auto& self = instance();

    // Restart script if at end.
    if (self._stepCount >= self._script.size()) {
        std::cerr << "pcsc-mock: WARNING: restarting script" << std::endl;
        self._stepCount = 0;
    }

    const auto& [expectedCommand, response] = self._script[self._stepCount];

    // Empty expected command means that any command is accepted.
    if (!expectedCommand.empty() && command != expectedCommand) {
        throw PcscMockError("At step "s + std::to_string(self._stepCount)
                            + ": unexcpected command '"s + bytes2hexstr(command) + "', expected '"s
                            + bytes2hexstr(expectedCommand) + "' instead"s);
    }

    ++self._stepCount;
    return response;
}

const PcscMock::byte_vector PcscMock::DEFAULT_CARD_ATR {0x1, 0x2, 0x3, 0x4};
#ifdef _WIN32
const PcscMock::string_t PcscMock::DEFAULT_READER_NAME {L"PcscMock-reader"s};
#else
const PcscMock::string_t PcscMock::DEFAULT_READER_NAME {"PcscMock-reader"s};
#endif

const PcscMock::byte_vector PcscMock::DEFAULT_COMMAND_APDU {0x2, 0x1, 0x3, 0x4};
const PcscMock::byte_vector PcscMock::DEFAULT_RESPONSE_APDU {0x90, 0x3};

const PcscMock::ApduScript PcscMock::DEFAULT_SCRIPT {{DEFAULT_COMMAND_APDU, DEFAULT_RESPONSE_APDU}};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4273)
__declspec(dllexport) const SCARD_IO_REQUEST g_rgSCardT0Pci = {SCARD_PROTOCOL_T0,
                                                               sizeof(SCARD_IO_REQUEST)};
__declspec(dllexport) const SCARD_IO_REQUEST g_rgSCardT1Pci = {SCARD_PROTOCOL_T1,
                                                               sizeof(SCARD_IO_REQUEST)};
__declspec(dllexport) const SCARD_IO_REQUEST g_rgSCardRawPci = {SCARD_PROTOCOL_RAW,
                                                                sizeof(SCARD_IO_REQUEST)};
#pragma warning(pop)
#else
MOCK_CONST SCARD_IO_REQUEST g_rgSCardT0Pci = {SCARD_PROTOCOL_T0, sizeof(SCARD_IO_REQUEST)};
MOCK_CONST SCARD_IO_REQUEST g_rgSCardT1Pci = {SCARD_PROTOCOL_T1, sizeof(SCARD_IO_REQUEST)};
MOCK_CONST SCARD_IO_REQUEST g_rgSCardRawPci = {SCARD_PROTOCOL_RAW, sizeof(SCARD_IO_REQUEST)};
#endif

#ifdef _MSC_VER
WINSCARDAPI LONG WINAPI SCardEstablishContext(_In_ DWORD, _Reserved_ LPCVOID, _Reserved_ LPCVOID,
                                              _Out_ LPSCARDCONTEXT context)
#else
LONG SCardEstablishContext(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT context)
#endif
{
    PcscMock::callScardFunction(__FUNCTION__);
    *context = 1;
    return PcscMock::returnValueForScardFunctionCall(__FUNCTION__);
}

#ifdef _MSC_VER
WINSCARDAPI LONG WINAPI SCardReleaseContext(SCARDCONTEXT)
#else
LONG SCardReleaseContext(SCARDCONTEXT)
#endif
{
    PcscMock::callScardFunction(__FUNCTION__);
    return PcscMock::returnValueForScardFunctionCall(__FUNCTION__);
}

#ifdef _MSC_VER // TODO: multibyte/Unicode API in Windows?
WINSCARDAPI LONG WINAPI SCardListReadersW(SCARDCONTEXT, LPCWSTR, LPWSTR mszReaders,
                                          LPDWORD pcchReaders)
#else
LONG SCardListReaders(SCARDCONTEXT, LPCSTR, LPSTR mszReaders, LPDWORD pcchReaders)
#endif
{
    PcscMock::callScardFunction("SCardListReaders");

    if (!pcchReaders)
        return SCARD_E_INVALID_PARAMETER;

    DWORD bufferLength = DWORD(PcscMock::DEFAULT_READER_NAME.size() + 1);

    if (mszReaders && *pcchReaders < bufferLength)
        return SCARD_E_INSUFFICIENT_BUFFER;

    auto returnValue = PcscMock::returnValueForScardFunctionCall("SCardListReaders");
    if (returnValue) {
        return returnValue;
    }

    *pcchReaders = bufferLength;

    if (!mszReaders)
        // if buffer not given, only output buffer length
        return SCARD_S_SUCCESS;

    auto buf = PcscMock::DEFAULT_READER_NAME;
    buf.insert(buf.cend(), 0);

    memcpy(mszReaders, buf.c_str(), buf.size() * sizeof(PcscMock::string_t::value_type));

    return SCARD_S_SUCCESS;
}

#ifdef _MSC_VER // TODO: multibyte/Unicode API in Windows?
WINSCARDAPI LONG WINAPI SCardConnectW(_In_ SCARDCONTEXT, _In_ LPCWSTR, _In_ DWORD,
                                      _In_ DWORD requestedProtocol, _Out_ LPSCARDHANDLE cardHandle,
                                      _Out_ LPDWORD protocolOut)
#else
LONG SCardConnect(SCARDCONTEXT, LPCSTR, DWORD, DWORD requestedProtocol, LPSCARDHANDLE cardHandle,
                  LPDWORD protocolOut)
#endif
{
    PcscMock::callScardFunction("SCardConnect");

    auto returnValue = PcscMock::returnValueForScardFunctionCall("SCardConnect");
    if (returnValue) {
        return returnValue;
    }

    // TODO: no RAW etc support
    if (requestedProtocol == SCARD_PROTOCOL_T0 || requestedProtocol == SCARD_PROTOCOL_T1) {
        *cardHandle = 0x0ff;
        *protocolOut = requestedProtocol;
    } else if (requestedProtocol == (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1)) {
        *cardHandle = 0x0ff;
        *protocolOut = SCARD_PROTOCOL_T1; // TODO: make configurable
    } else {
        return SCARD_E_INVALID_PARAMETER;
    }

    return SCARD_S_SUCCESS;
}

#ifdef _MSC_VER
WINSCARDAPI LONG WINAPI SCardDisconnect(_In_ SCARDHANDLE, _In_ DWORD)
#else
LONG SCardDisconnect(SCARDHANDLE, DWORD)
#endif
{
    PcscMock::callScardFunction(__FUNCTION__);
    return PcscMock::returnValueForScardFunctionCall(__FUNCTION__);
}

#ifdef _MSC_VER // TODO: multibyte/Unicode API in Windows?
WINSCARDAPI LONG WINAPI SCardGetStatusChangeW(SCARDCONTEXT, DWORD,
                                              LPSCARD_READERSTATEW rgReaderStates, DWORD cReaders)
#else
LONG SCardGetStatusChange(SCARDCONTEXT, DWORD, LPSCARD_READERSTATE rgReaderStates, DWORD cReaders)
#endif
{
    PcscMock::callScardFunction("SCardGetStatusChange");

    if (!rgReaderStates || cReaders != 1)
        return SCARD_E_INVALID_PARAMETER;

    auto returnValue = PcscMock::returnValueForScardFunctionCall("SCardGetStatusChange");
    if (returnValue) {
        return returnValue;
    }

    const auto& atr = PcscMock::atr();

    rgReaderStates->szReader = PcscMock::DEFAULT_READER_NAME.c_str();
    size_t atrSize = atr.size();
    memcpy(rgReaderStates->rgbAtr, atr.data(), atrSize);
    rgReaderStates->cbAtr = DWORD(atrSize);
    rgReaderStates->dwEventState = SCARD_STATE_PRESENT;

    return SCARD_S_SUCCESS;
}

#ifdef _MSC_VER
WINSCARDAPI LONG WINAPI SCardBeginTransaction(_In_ SCARDHANDLE)
#else
LONG SCardBeginTransaction(SCARDHANDLE)
#endif
{
    PcscMock::callScardFunction(__FUNCTION__);
    return PcscMock::returnValueForScardFunctionCall(__FUNCTION__);
}

#ifdef _MSC_VER
WINSCARDAPI LONG WINAPI SCardEndTransaction(_In_ SCARDHANDLE, _In_ DWORD)
#else
LONG SCardEndTransaction(SCARDHANDLE, DWORD)
#endif
{
    PcscMock::callScardFunction(__FUNCTION__);
    return PcscMock::returnValueForScardFunctionCall(__FUNCTION__);
}

#ifdef _MSC_VER
WINSCARDAPI LONG WINAPI SCardTransmit(_In_ SCARDHANDLE, _In_ LPCSCARD_IO_REQUEST,
                                      _In_reads_bytes_(commandBytesLength) LPCBYTE commandBytes,
                                      _In_ DWORD commandBytesLength, _Inout_opt_ LPSCARD_IO_REQUEST,
                                      _Out_writes_bytes_(*responseBytesLength) LPBYTE responseBytes,
                                      _Inout_ LPDWORD responseBytesLength)
#else
LONG SCardTransmit(SCARDHANDLE, LPCSCARD_IO_REQUEST, LPCBYTE commandBytes, DWORD commandBytesLength,
                   LPSCARD_IO_REQUEST, LPBYTE responseBytes, LPDWORD responseBytesLength)
#endif
{
    PcscMock::callScardFunction(__FUNCTION__);

    if (!commandBytes || !responseBytes || commandBytesLength < 1 || *responseBytesLength < 1)
        return SCARD_E_INVALID_PARAMETER;

    PcscMock::byte_vector command {commandBytes, commandBytes + commandBytesLength};
    PcscMock::byte_vector response = PcscMock::responseForApduCommand(command);

    DWORD responseLenght = DWORD(response.size());

    if (*responseBytesLength < responseLenght)
        return SCARD_E_INSUFFICIENT_BUFFER;

    auto returnValue = PcscMock::returnValueForScardFunctionCall(__FUNCTION__);
    if (returnValue) {
        return returnValue;
    }

    *responseBytesLength = responseLenght;

    memcpy(responseBytes, response.data(), responseLenght);

    return SCARD_S_SUCCESS;
}

#ifdef _MSC_VER
WINSCARDAPI LONG WINAPI SCardControl(_In_ SCARDHANDLE, _In_ DWORD,
                                     _In_reads_bytes_(cbInBufferSize) LPCVOID, _In_ DWORD,
                                     _Out_writes_bytes_(cbOutBufferSize) LPVOID, _In_ DWORD,
                                     _Out_ LPDWORD bytesReturned)
#else
LONG SCardControl(SCARDHANDLE, DWORD, LPCVOID, DWORD, LPVOID, DWORD, LPDWORD bytesReturned)
#endif
{
    PcscMock::callScardFunction(__FUNCTION__);
    *bytesReturned = 0;
    return PcscMock::returnValueForScardFunctionCall(__FUNCTION__);
}

#ifdef _MSC_VER
WINSCARDAPI LONG WINAPI SCardFreeMemory(_In_ SCARDCONTEXT, _In_ LPCVOID)
#else
LONG SCardFreeMemory(SCARDCONTEXT, LPCVOID)
#endif
{
    PcscMock::callScardFunction(__FUNCTION__);
    return PcscMock::returnValueForScardFunctionCall(__FUNCTION__);
}
