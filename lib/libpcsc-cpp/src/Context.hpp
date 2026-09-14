// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#pragma once

#include "pcsc-cpp/pcsc-cpp.hpp"
#include "pcsc-cpp/pcsc-cpp-utils.hpp"

#include "SCardCall.hpp"

#include "pcsc-cpp/comp_winscard.hpp"

namespace pcsc_cpp
{

class Context
{
public:
    Context()
    {
        SCard(EstablishContext, DWORD(SCARD_SCOPE_USER), nullptr, nullptr, &contextHandle);
        if (!contextHandle) {
            THROW(ScardError,
                  "Context:SCardEstablishContext: service unavailable "
                  "(null context handle)");
        }
    }

    ~Context()
    {
        if (contextHandle) {
            // Cannot throw in destructor, so cannot use the SCard() macro here.
            auto result = SCardReleaseContext(contextHandle);
            contextHandle = 0;
            (void)result; // TODO: Log result here in case it is not OK.
        }
    }

    PCSC_CPP_DISABLE_COPY_MOVE(Context);

    SCARDCONTEXT handle() const { return contextHandle; }

private:
    SCARDCONTEXT contextHandle = 0;
};

} // namespace pcsc_cpp
