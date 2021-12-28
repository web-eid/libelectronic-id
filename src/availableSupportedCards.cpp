/*
 * Copyright (c) 2020-2022 Estonian Information System Authority
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

#include "electronic-id/electronic-id.hpp"

namespace
{

using namespace electronic_id;

inline CardInfo::ptr connectToCard(const pcsc_cpp::Reader& reader)
{
    auto eid = getElectronicID(reader);
    return std::make_shared<CardInfo>(reader, eid);
}

} // namespace

namespace electronic_id
{

std::vector<CardInfo::ptr> availableSupportedCards()
{
    std::vector<pcsc_cpp::Reader> readers;
    try {
        readers = pcsc_cpp::listReaders();
        std::vector<CardInfo::ptr> cards;

        if (readers.empty()) {
            throw AutoSelectFailed(AutoSelectFailed::Reason::NO_READERS);
        }

        auto seenCard = false;
        for (const auto& reader : readers) {
            if (!reader.isCardInserted()) {
                continue;
            }
            seenCard = true;
            if (isCardSupported(reader.cardAtr)) {
                cards.push_back(connectToCard(reader));
            }
        }

        if (!seenCard) {
            throw AutoSelectFailed(readers.size() > 1
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
