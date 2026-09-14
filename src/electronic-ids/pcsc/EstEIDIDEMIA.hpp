// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#pragma once

#include "EIDIDEMIA.hpp"

// ESTEID specification:
// https://installer.id.ee/media/id2019/TD-ID1-Chip-App.pdf

namespace electronic_id
{

class EstEIDIDEMIAV1 : public EIDIDEMIA
{
public:
    using EIDIDEMIA::EIDIDEMIA;

private:
    constexpr PinMinMaxLength signingPinMinMaxLength() const override { return {5, 12}; }
    std::string name() const override { return "EstEID IDEMIA v1"; }
    Type type() const override { return EstEID; }
};

} // namespace electronic_id
