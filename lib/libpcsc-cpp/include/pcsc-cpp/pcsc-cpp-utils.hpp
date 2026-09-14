// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#pragma once

#include <string>
#include <sstream>
#include <iomanip>

namespace pcsc_cpp
{

/** Convert bytes to hex string. */
inline std::ostream& operator<<(std::ostream& os, const byte_vector& data)
{
    os << std::setfill('0') << std::hex;
    for (const auto byte : data)
        os << std::setw(2) << short(byte);
    return os << std::setfill(' ') << std::dec;
}

/** Convert the given integer to a hex string. */
template <typename T>
inline std::string int2hexstr(const T value)
{
    std::ostringstream hexStringBuilder;

    hexStringBuilder << "0x" << std::setfill('0') << std::setw(sizeof(long) * 2) << std::hex
                     << value;

    return hexStringBuilder.str();
}

/** Remove absolute path prefix until 'src' from the given path, '/path/to/src/main.cpp' becomes
 * 'src/main.cpp'. */
constexpr const char* removeAbsolutePathPrefix(std::string_view filePath)
{
    const auto lastSrc = filePath.rfind("src");
    return lastSrc == std::string::npos ? filePath.data() : filePath.substr(lastSrc).data();
}

} // namespace pcsc_cpp

#define THROW_WITH_CALLER_INFO(ExceptionType, message, file, line, func)                           \
    throw ExceptionType(std::string(message) + " in " + pcsc_cpp::removeAbsolutePathPrefix(file)   \
                        + ':' + std::to_string(line) + ':' + (func))

#define THROW(ExceptionType, message)                                                              \
    THROW_WITH_CALLER_INFO(ExceptionType, message, __FILE__, __LINE__, __func__)

#define REQUIRE_NON_NULL(val)                                                                      \
    if (!(val)) {                                                                                  \
        THROW(std::logic_error, "Null " #val);                                                     \
    }
