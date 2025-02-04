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

#include "Context.hpp"

#include <algorithm>
#include <map>
#include <memory>

namespace
{

using namespace pcsc_cpp;

inline DWORD updateReaderNamesBuffer(const SCARDCONTEXT ctx, string_t::value_type* buffer,
                                     const DWORD bufferLength = 0)
{
    auto bufferLengthOut = bufferLength;
    SCard(ListReaders, ctx, nullptr, buffer, &bufferLengthOut);
    return bufferLengthOut;
}

std::vector<SCARD_READERSTATE> getReaderStates(const SCARDCONTEXT ctx, const string_t& readerNames)
{
    auto readerStates = std::vector<SCARD_READERSTATE> {};
    // Reader names are \0 separated and end with double \0.
    for (const auto* name = readerNames.c_str(); *name;
         name += string_t::traits_type::length(name) + 1) {
        readerStates.push_back({name,
                                nullptr,
                                SCARD_STATE_UNAWARE,
                                SCARD_STATE_UNAWARE,
                                0,
                                {
                                    0,
                                }});
    }

    if (readerStates.empty())
        return readerStates;

    SCard(GetStatusChange, ctx, 0U, readerStates.data(), DWORD(readerStates.size()));

    return readerStates;
}

inline flag_set<Reader::Status> flagSetFromReaderState(const DWORD readerState)
{
    if (!readerState) {
        return flag_set<Reader::Status> {Reader::Status::UNAWARE};
    }

    static const std::map<DWORD, Reader::Status> READER_STATUS_MAP = {
        // SCARD_STATE_UNAWARE is zero and covered with (!readerState) above.
        {SCARD_STATE_IGNORE, Reader::Status::IGNORE},
        {SCARD_STATE_CHANGED, Reader::Status::CHANGED},
        {SCARD_STATE_UNKNOWN, Reader::Status::UNKNOWN},
        {SCARD_STATE_UNAVAILABLE, Reader::Status::UNAVAILABLE},
        {SCARD_STATE_EMPTY, Reader::Status::EMPTY},
        {SCARD_STATE_PRESENT, Reader::Status::PRESENT},
        {SCARD_STATE_ATRMATCH, Reader::Status::ATRMATCH},
        {SCARD_STATE_EXCLUSIVE, Reader::Status::EXCLUSIVE},
        {SCARD_STATE_INUSE, Reader::Status::INUSE},
        {SCARD_STATE_MUTE, Reader::Status::MUTE},
        {SCARD_STATE_UNPOWERED, Reader::Status::UNPOWERED}};

    auto result = flag_set<Reader::Status> {};

    for (const auto& [key, value] : READER_STATUS_MAP) {
        if (readerState & key) {
            result.set(value);
        }
    }

    return result;
}

string_t populateReaderNames(const SCARDCONTEXT ctx)
{
    // Buffer length is in characters, not bytes.
    const auto bufferLength = updateReaderNamesBuffer(ctx, nullptr);

    auto readerNames = string_t(bufferLength, 0);

    // The returned buffer length is no longer useful, ignore it.
    updateReaderNamesBuffer(ctx, readerNames.data(), bufferLength);

    return readerNames;
}

} // anonymous namespace

namespace pcsc_cpp
{

std::vector<Reader> listReaders()
{
    auto ctx = std::make_shared<Context>();
    std::vector<Reader> readers;

    try {
        auto readerNames = populateReaderNames(ctx->handle());

        for (const auto& readerState : getReaderStates(ctx->handle(), readerNames)) {
            readers.emplace_back(
                ctx, readerState.szReader,
                byte_vector {readerState.rgbAtr, std::next(readerState.rgbAtr, readerState.cbAtr)},
                flagSetFromReaderState(readerState.dwEventState));
        }
    } catch (const ScardNoReadersError& /* e */) {
    }
    return readers;
}

} // namespace pcsc_cpp
