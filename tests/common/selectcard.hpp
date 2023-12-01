#pragma once

#include "electronic-id/electronic-id.hpp"

#include <stdexcept>

inline electronic_id::CardInfo::ptr autoSelectSupportedCard() {
    using namespace electronic_id;

    auto cardList = availableSupportedCards();
    if (cardList.empty()) {
        throw std::logic_error("test::autoSelectSupportedCard(): No smart cards attached");
    }

    return  cardList[0];
}

inline std::ostream &operator<<(std::ostream &os, const pcsc_cpp::byte_vector &data)
{
    return os << pcsc_cpp::bytes2hexstr(data);
}
