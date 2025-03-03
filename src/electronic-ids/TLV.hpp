/*
 * Copyright (c) 2025 Estonian Information System Authority
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
#include "pcsc-cpp/pcsc-cpp-utils.hpp"

namespace electronic_id
{

/**
 * Represents a single Tag-Length-Value structure used in DER-encoded eID card files.
 *
 * The constructor parses the tag and length from the provided byte range,
 * then adjusts its iterators so that `begin` and `end` reference only the value bytes.
 * If the TLV is empty, `operator bool()` returns false.
 */
struct TLV
{
    using byte_vector = pcsc_cpp::byte_vector;
    uint16_t tag {};
    uint32_t length {};
    byte_vector::const_iterator begin;
    byte_vector::const_iterator end;

    PCSC_CPP_CONSTEXPR_VECTOR explicit TLV(const byte_vector& data) :
        TLV(data.cbegin(), data.cend())
    {
    }

    PCSC_CPP_CONSTEXPR_VECTOR TLV(byte_vector::const_iterator _begin,
                                  byte_vector::const_iterator _end) : begin(_begin), end(_end)
    {
        if (!*this) {
            return;
        }

        tag = *begin++;
        if ((tag & 0x1F) == 0x1F) { // Multi-byte tag
            if (!*this) {
                THROW(std::invalid_argument, "Invalid TLV: Unexpected end of tag");
            }
            tag = (tag << 8) | (*begin++);
        }

        if (!*this) {
            THROW(std::invalid_argument, "Invalid TLV: Missing length field");
        }

        length = *begin++;
        if (length & 0x80) { // Extended length encoding
            auto num_bytes = uint8_t(length & 0x7F);
            if (num_bytes == 0 || num_bytes > 4 || std::distance(begin, end) < num_bytes) {
                THROW(std::invalid_argument, "Invalid TLV: Incorrect extended length encoding");
            }

            length = 0;
            for (uint8_t i = 0; i < num_bytes; ++i) {
                length = (length << 8) | (*begin++);
            }
        }

        if (std::distance(begin, end) < length) {
            THROW(std::invalid_argument, "Invalid TLV: Insufficient value data");
        }
    }

    PCSC_CPP_CONSTEXPR_VECTOR TLV child() const { return {begin, begin + length}; }

    PCSC_CPP_CONSTEXPR_VECTOR TLV& operator++() { return *this = {begin + length, end}; }

    template <typename... Tags>
    static PCSC_CPP_CONSTEXPR_VECTOR TLV path(TLV tlv, uint16_t tag, Tags... tags)
    {
        for (; tlv; ++tlv) {
            if (tlv.tag == tag) {
                if constexpr (sizeof...(tags) > 0) {
                    return path(tlv.child(), uint16_t(tags)...);
                }
                return tlv;
            }
        }
        return TLV({});
    }
    template <typename... Tags>
    static PCSC_CPP_CONSTEXPR_VECTOR TLV path(const byte_vector& data, uint16_t tag, Tags... tags)
    {
        return path(TLV(data), tag, tags...);
    }

    constexpr operator bool() const noexcept { return begin != end; }
};

} // namespace electronic_id
