// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "pcsc-cpp/pcsc-cpp.hpp"

#include "gtest/gtest.h"

#include <iostream>

TEST(pcsc_cpp_test, listReaders)
{
    using namespace pcsc_cpp;

    auto readers = listReaders();
    for (const auto& reader : readers) {
#ifdef _WIN32
        std::wcout << L"Reader name: '" << reader.name << L"', card status: '"
                   << (reader.isCardPresent ? L"PRESENT" : L"ABSENT") << L"'" << std::endl;
#else
        std::cout << "Reader name: '" << reader.name << "', card status: '"
                  << (reader.isCardPresent ? "PRESENT" : "ABSENT") << "'" << std::endl;
#endif
    }
}
