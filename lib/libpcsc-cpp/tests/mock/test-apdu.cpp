// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "pcsc-cpp/pcsc-cpp.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <type_traits>

using namespace pcsc_cpp;

#define CONSTEXPR_CHECK(...)                                                                       \
    static_assert((__VA_ARGS__));                                                                  \
    EXPECT_TRUE((__VA_ARGS__))

// A throw during constant evaluation makes the call a non-constant expression, so check that at
// compile time and the thrown exception type at runtime.
#define CONSTEXPR_EXPECT_THROW(statement, exception)                                               \
    static_assert(!isConstantExpression<[] { statement; }>);                                       \
    EXPECT_THROW(statement, exception)

namespace
{

template <auto F>
constexpr bool isConstantExpression = requires { typename std::bool_constant<(F(), true)>; };

constexpr byte_vector pinWithCapacity(std::initializer_list<byte_type> digits, size_t capacity)
{
    byte_vector pin;
    pin.reserve(capacity);
    pin.insert(pin.end(), digits);
    return pin;
}

constexpr bool equals(const CommandApdu& apdu, std::initializer_list<byte_type> expected)
{
    const byte_vector& actual = apdu;
    return std::equal(actual.begin(), actual.end(), expected.begin(), expected.end());
}

} // namespace

TEST(CommandApduTest, case1HeaderOnly)
{
    CONSTEXPR_CHECK(equals(CommandApdu {0x00, 0xA4, 0x04, 0x0C}, {0x00, 0xA4, 0x04, 0x0C}));
}

TEST(CommandApduTest, case2HeaderAndLe)
{
    CONSTEXPR_CHECK(
        equals(CommandApdu {0x00, 0xB0, 0x00, 0x00, 0x10}, {0x00, 0xB0, 0x00, 0x00, 0x10}));
}

TEST(CommandApduTest, case3HeaderLcAndData)
{
    CONSTEXPR_CHECK(equals(CommandApdu {0x00, 0xA4, 0x04, 0x0C, byte_vector {0xA0, 0x00, 0x01}},
                           {0x00, 0xA4, 0x04, 0x0C, 0x03, 0xA0, 0x00, 0x01}));
}

TEST(CommandApduTest, case4HeaderLcDataAndLe)
{
    CONSTEXPR_CHECK(equals(CommandApdu {0x00, 0x2A, 0x9E, 0x9A, byte_vector {0x01, 0x02}, 0x00},
                           {0x00, 0x2A, 0x9E, 0x9A, 0x02, 0x01, 0x02, 0x00}));
}

TEST(CommandApduTest, case3AcceptsMaxDataSize)
{
    CONSTEXPR_CHECK([] {
        CommandApdu apdu {0x00, 0xD6, 0x00, 0x00, byte_vector(CommandApdu::MAX_DATA_SIZE, 0xAA)};
        const byte_vector& d = apdu;
        return d.size() == CommandApdu::APDU_HEADER_AND_LC_SIZE + CommandApdu::MAX_DATA_SIZE
            && d[4] == 0xFF && d.back() == 0xAA;
    }());
}

TEST(CommandApduTest, case3RejectsDataOverMaxSize)
{
    CONSTEXPR_EXPECT_THROW(
        (CommandApdu {0x00, 0xD6, 0x00, 0x00, byte_vector(CommandApdu::MAX_DATA_SIZE + 1, 0xAA)}),
        std::invalid_argument);
    CONSTEXPR_EXPECT_THROW((CommandApdu {0x00, 0xD6, 0x00, 0x00,
                                         byte_vector(CommandApdu::MAX_DATA_SIZE + 1, 0xAA), 0x00}),
                           std::invalid_argument);
}

TEST(CommandApduTest, case3RejectsEmptyData)
{
    CONSTEXPR_EXPECT_THROW((CommandApdu {0x00, 0xA4, 0x04, 0x0C, byte_vector {}}),
                           std::invalid_argument);
    CONSTEXPR_EXPECT_THROW((CommandApdu {0x00, 0xA4, 0x04, 0x0C, byte_vector {}, 0x00}),
                           std::invalid_argument);
    CONSTEXPR_EXPECT_THROW(CommandApdu::select(0x04, {}), std::invalid_argument);
    CONSTEXPR_EXPECT_THROW(CommandApdu::selectEF(0x02, {}), std::invalid_argument);
}

TEST(CommandApduTest, withLeAppendsLeToCase1)
{
    CONSTEXPR_CHECK(equals(CommandApdu {CommandApdu {0x00, 0xCA, 0x01, 0x00}, 0x20},
                           {0x00, 0xCA, 0x01, 0x00, 0x20}));
}

TEST(CommandApduTest, withLeReplacesLeInCase2)
{
    CONSTEXPR_CHECK(equals(CommandApdu {CommandApdu {0x00, 0xB0, 0x00, 0x00, 0x00}, 0xE7},
                           {0x00, 0xB0, 0x00, 0x00, 0xE7}));
}

TEST(CommandApduTest, withLeAppendsLeToCase3)
{
    CONSTEXPR_CHECK(
        equals(CommandApdu {CommandApdu {0x00, 0x88, 0x00, 0x00, byte_vector {0x11}}, 0x00},
               {0x00, 0x88, 0x00, 0x00, 0x01, 0x11, 0x00}));
}

TEST(CommandApduTest, withLeReplacesLeInCase4)
{
    CONSTEXPR_CHECK(equals(
        CommandApdu {CommandApdu {0x00, 0x88, 0x00, 0x00, byte_vector {0x11, 0x22}, 0x00}, 0x40},
        {0x00, 0x88, 0x00, 0x00, 0x02, 0x11, 0x22, 0x40}));
}

TEST(CommandApduTest, select)
{
    CONSTEXPR_CHECK(equals(CommandApdu::select(0x08, {0x3F, 0x00, 0xAD, 0xF1}),
                           {0x00, 0xA4, 0x08, 0x0C, 0x04, 0x3F, 0x00, 0xAD, 0xF1}));
}

TEST(CommandApduTest, selectEF)
{
    CONSTEXPR_CHECK(equals(CommandApdu::selectEF(0x02, {0xD0, 0x01}),
                           {0x00, 0xA4, 0x02, 0x04, 0x02, 0xD0, 0x01, 0x00}));
}

TEST(CommandApduTest, readBinarySplitsOffsetIntoP1P2)
{
    CONSTEXPR_CHECK(equals(CommandApdu::readBinary(0x1234, 0xE7), {0x00, 0xB0, 0x12, 0x34, 0xE7}));
    CONSTEXPR_CHECK(equals(CommandApdu::readBinary(0, 0x00), {0x00, 0xB0, 0x00, 0x00, 0x00}));
}

TEST(CommandApduTest, getResponse)
{
    CONSTEXPR_CHECK(equals(CommandApdu::getResponse(), {0x00, 0xC0, 0x00, 0x00, 0x00}));
    CONSTEXPR_CHECK(equals(CommandApdu::getResponse(0x20), {0x00, 0xC0, 0x00, 0x00, 0x20}));
}

TEST(CommandApduTest, verifyPadsPin)
{
    CONSTEXPR_CHECK([] {
        byte_vector pin;
        pin.reserve(8 + CommandApdu::APDU_HEADER_AND_LC_SIZE);
        pin.insert(pin.end(), {'1', '2', '3', '4'});
        return equals(CommandApdu::verify(0x81, std::move(pin), 8, 0xFF),
                      {0x00, 0x20, 0x00, 0x81, 0x08, '1', '2', '3', '4', 0xFF, 0xFF, 0xFF, 0xFF});
    }());
}

TEST(CommandApduTest, verifyWithoutPaddingKeepsPin)
{
    CONSTEXPR_CHECK([] {
        byte_vector pin;
        pin.reserve(12 + CommandApdu::APDU_HEADER_AND_LC_SIZE);
        pin.insert(pin.end(), {'1', '2', '3', '4'});
        return equals(CommandApdu::verify(0x02, std::move(pin), 4, 0x00),
                      {0x00, 0x20, 0x00, 0x02, 0x04, '1', '2', '3', '4'});
    }());
}

TEST(CommandApduTest, verifyPaddingOnly)
{
    CONSTEXPR_CHECK(equals(CommandApdu::verify(0x85, 6, 0xFF),
                           {0x00, 0x20, 0x00, 0x85, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
}

TEST(CommandApduTest, verifyRejectsPinBufferWithoutPaddingCapacity)
{
    CONSTEXPR_EXPECT_THROW(CommandApdu::verify(0x81, byte_vector {'1', '2', '3', '4'}, 64, 0xFF),
                           std::invalid_argument);
}

TEST(CommandApduTest, verifyRejectsPinLongerThanPaddingLength)
{
    CONSTEXPR_EXPECT_THROW(
        CommandApdu::verify(
            0x81, pinWithCapacity({'1', '2', '3', '4', '5', '6', '7', '8', '9'}, 16), 8, 0xFF),
        std::invalid_argument);
}

TEST(CommandApduTest, verifyRejectsEmptyPinWithoutPadding)
{
    CONSTEXPR_EXPECT_THROW(CommandApdu::verify(0x81, 0, 0xFF), std::invalid_argument);
    CONSTEXPR_EXPECT_THROW(CommandApdu::verify(0x81, byte_vector {}, 0, 0xFF),
                           std::invalid_argument);
}
