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

#include "pcsc-cpp/pcsc-cpp.hpp"
#include "pcsc-cpp/pcsc-cpp-utils.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

using namespace pcsc_cpp;
using namespace std::string_literals;

namespace
{

class UnexpectedResponseError : public Error
{
public:
    explicit UnexpectedResponseError(const CommandApdu& command, const ResponseApdu& response,
                                     const char* file, const int line,
                                     const char* callerFunctionName) :
        Error("transmitApduWithExpectedResponse(): Unexpected response to command '"s + command
              + "' - expected '9000', got '"s + response + "' in " + removeAbsolutePathPrefix(file)
              + ':' + std::to_string(line) + ':' + callerFunctionName)
    {
    }
};

} // namespace

namespace pcsc_cpp
{

std::ostream& operator<<(std::ostream& os, const pcsc_cpp::byte_vector& data)
{
    os << std::setfill('0') << std::hex;
    for (const auto byte : data)
        os << std::setw(2) << short(byte);
    return os << std::setfill(' ') << std::dec;
}

std::string operator+(std::string lhs, const byte_vector& rhs)
{
    lhs.reserve(lhs.size() + rhs.size() * 2);
    std::ostringstream hexStringBuilder(std::move(lhs), std::ios::ate);
    hexStringBuilder << rhs;
    return hexStringBuilder.str();
}

void transmitApduWithExpectedResponse(const SmartCard& card, const CommandApdu& command)
{
    const auto response = card.transmit(command);
    if (!response.isOK()) {
        throw UnexpectedResponseError(command, response, __FILE__, __LINE__, __func__);
    }
}

byte_vector readBinary(const SmartCard& card, const uint16_t length, byte_type blockLength)
{
    byte_vector resultBytes;
    resultBytes.reserve(length);
    while (resultBytes.size() < length) {
        byte_type chunk = byte_type(std::min<size_t>(length - resultBytes.size(), blockLength));
        auto response = card.transmit(CommandApdu::readBinary(uint16_t(resultBytes.size()), chunk));
        if (chunk > 0 && response.data.size() != chunk) {
            THROW(Error,
                  "Length mismatch, expected "s + std::to_string(chunk) + ", received "
                      + std::to_string(response.data.size()) + " bytes");
        }
        resultBytes.insert(resultBytes.end(), response.data.cbegin(), response.data.cend());
    }
    if (resultBytes.size() != length) {
        THROW(Error,
              "Length mismatch, expected "s + std::to_string(length) + ", received "
                  + std::to_string(resultBytes.size()) + " bytes");
    }
    return resultBytes;
}

} // namespace pcsc_cpp
