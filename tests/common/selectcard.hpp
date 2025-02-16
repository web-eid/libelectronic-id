#pragma once

#include "electronic-id/electronic-id.hpp"

#include <stdexcept>
#include <iostream>

inline electronic_id::ElectronicID::ptr autoSelectSupportedCard()
{
    using namespace electronic_id;

    auto cardList = availableSupportedCards();
    if (cardList.empty()) {
        throw std::logic_error("test::autoSelectSupportedCard(): No smart cards attached");
    }

    return cardList[0];
}

inline void printCardInfo(const electronic_id::ElectronicID& eid)
{
    std::cout << "Selected card: " << eid.name() << '\n';
#ifdef _WIN32
    std::wcout << L"Card reader: " << eid.smartcard().readerName() << L'\n';
#else
    std::cout << "Card reader: " << eid.smartcard().readerName() << '\n';
#endif
    std::cout << "Protocol: " << static_cast<int>(eid.smartcard().protocol()) << '\n';
}
