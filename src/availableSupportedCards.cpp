// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "electronic-id/electronic-id.hpp"

#ifdef _WIN32
#include "electronic-ids/ms-cryptoapi/listMsCryptoApiElectronicIDs.hpp"
#endif

namespace electronic_id
{

std::vector<ElectronicID::ptr> availableSupportedCards()
{
    std::vector<pcsc_cpp::Reader> readers;
    try {
        readers = pcsc_cpp::listReaders();
        std::vector<ElectronicID::ptr> cards;

        auto seenCard = false;
        // The list may be empty, but we cannot throw yet due to the listMsCryptoApiElectronicIDs()
        // call in Windows.
        for (const auto& reader : readers) {
            if (!reader.isCardPresent) {
                continue;
            }
            seenCard = true;
            if (isCardSupported(reader.cardAtr)) {
                cards.push_back(getElectronicID(reader));
            }
        }

#ifdef _WIN32
        // In Windows, also include CryptoAPI tokens.
        // Initially, CryptoAPI tokens will be included only if there are
        // no tier 1 or 2 cards present.
        if (cards.empty()) {
            cards = listMsCryptoApiElectronicIDs();
            if (!cards.empty()) {
                seenCard = true;
            }
        }
#endif

        if (!seenCard) {
            throw AutoSelectFailed(readers.empty() ? AutoSelectFailed::Reason::NO_READERS
                                       : readers.size() > 1
                                       ? AutoSelectFailed::Reason::MULTIPLE_READERS_NO_CARD
                                       : AutoSelectFailed::Reason::SINGLE_READER_NO_CARD);
        }

        if (cards.empty()) {
            throw AutoSelectFailed(
                readers.size() > 1 ? AutoSelectFailed::Reason::MULTIPLE_READERS_NO_SUPPORTED_CARD
                                   : AutoSelectFailed::Reason::SINGLE_READER_UNSUPPORTED_CARD);
        }

        return cards;

    } catch (const pcsc_cpp::ScardServiceNotRunningError&) {
        throw AutoSelectFailed(AutoSelectFailed::Reason::SERVICE_NOT_RUNNING);
    } catch (const pcsc_cpp::ScardNoReadersError&) {
        throw AutoSelectFailed(AutoSelectFailed::Reason::NO_READERS);
    } catch (const pcsc_cpp::ScardNoCardError&) {
        throw AutoSelectFailed(readers.size() > 1
                                   ? AutoSelectFailed::Reason::MULTIPLE_READERS_NO_CARD
                                   : AutoSelectFailed::Reason::SINGLE_READER_NO_CARD);
    } catch (const pcsc_cpp::ScardCardRemovedError&) {
        throw AutoSelectFailed(readers.size() > 1
                                   ? AutoSelectFailed::Reason::MULTIPLE_READERS_NO_CARD
                                   : AutoSelectFailed::Reason::SINGLE_READER_NO_CARD);
    }
}

} // namespace electronic_id
