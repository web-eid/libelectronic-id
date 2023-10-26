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

#pragma once

#include <string>
#include <set>
#include <map>
#include <vector>
#include <stdexcept>
#include <stdint.h>

#ifdef _WIN32
using MOCK_LONG = int32_t;
#else
using MOCK_LONG = uint32_t;
#endif

class PcscMockError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

class PcscMock
{
public:
    typedef std::vector<unsigned char> byte_vector;
    // An APDU script is a list of request-response APDU pairs.
    typedef std::vector<std::pair<byte_vector, byte_vector>> ApduScript;
    // Define local string type so that we can use wstring in Windows if needed.
#ifdef _WIN32
    using string_t = std::wstring;
#else
    using string_t = std::string;
#endif

    static void callScardFunction(const std::string& function)
    {
        instance()._recordedCalls.insert(function);
    }

    static bool wasScardFunctionCalled(const std::string& scardFunction)
    {
        return instance()._recordedCalls.find(scardFunction) != instance()._recordedCalls.end();
    }

    static void addReturnValueForScardFunctionCall(const std::string& scardFunctionName,
                                                   MOCK_LONG returnValue)
    {
        instance()._scardCallReturnValues[scardFunctionName] = returnValue;
    }

    static uint32_t returnValueForScardFunctionCall(const std::string& scardFunctionName)
    {
        // If the key does not exist, then std::map inserts it with a zero-initialized value,
        // this means that default return value is SCARD_S_SUCCESS.
        return instance()._scardCallReturnValues[scardFunctionName];
    }

    static byte_vector responseForApduCommand(const byte_vector& command);

    static void reset()
    {
        auto& self = instance();

        self._recordedCalls.clear();
        self._scardCallReturnValues.clear();
        self._atr = DEFAULT_CARD_ATR;
        self._script = DEFAULT_SCRIPT;
        self._stepCount = 0;
    }

    static void setApduScript(const ApduScript& script)
    {
        auto& self = instance();
        self._script = script;
        self._stepCount = 0;
    }

    static const byte_vector& atr() { return instance()._atr; }
    static void setAtr(const byte_vector& atr) { instance()._atr = atr; }

    static const byte_vector DEFAULT_CARD_ATR;
    static const string_t DEFAULT_READER_NAME;

    static const byte_vector DEFAULT_COMMAND_APDU;
    static const byte_vector DEFAULT_RESPONSE_APDU;
    static const ApduScript DEFAULT_SCRIPT;

private:
    PcscMock() = default;
    ~PcscMock() = default;

    // The rule of five (C++ Core guidelines C.21).
    PcscMock(const PcscMock&) = delete;
    PcscMock& operator=(const PcscMock&) = delete;
    PcscMock(PcscMock&&) = delete;
    PcscMock& operator=(PcscMock&&) = delete;

    static PcscMock& instance()
    {
        static PcscMock self;
        return self;
    }

    std::set<std::string> _recordedCalls;
    std::map<std::string, MOCK_LONG> _scardCallReturnValues;
    byte_vector _atr = DEFAULT_CARD_ATR;
    ApduScript _script = DEFAULT_SCRIPT;
    size_t _stepCount = 0;
};
