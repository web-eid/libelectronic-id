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

#pragma once

#include <type_traits>
#include <utility>
#include <memory>

template <class U, typename T>
[[nodiscard]]
constexpr auto make_unique_ptr(U* t, T d) noexcept
{
    return std::unique_ptr<U, T>(t, d);
}

// This is a temporary replacement for the <experimental/scope> header from
// Version 3 of the C++ Extensions for Library Fundamentals as defined in
// https://cplusplus.github.io/fundamentals-ts/v3.html and
// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2014/n4189.pdf.

namespace stdext
{

template <typename ExitFunction>
class scope_exit
{
public:
    // Construction.
    template <typename ExitFunctionPtr>
    explicit scope_exit(ExitFunctionPtr&& f) noexcept :
        exit_function(std::forward<ExitFunctionPtr>(f))
    {
    }

    // Move.
    scope_exit(scope_exit&& rhs) noexcept :
        exit_function(std::move(rhs.exit_function)),
        execute_on_destruction {rhs.execute_on_destruction}
    {
        rhs.release();
    }

    // Release.
    ~scope_exit() noexcept
    {
        if (execute_on_destruction) {
            try {
                exit_function();
            } catch (...) {
                // Prevent exceptions from leaving destructors.
            }
        }
    }

    // The Rule of Five (C++ Core guidelines C.21).
    scope_exit(scope_exit const&) = delete;
    void operator=(scope_exit const&) = delete;
    scope_exit& operator=(scope_exit&&) = delete;

    void release() noexcept { execute_on_destruction = false; }

private:
    ExitFunction exit_function;
    bool execute_on_destruction {true};
};

// Factory function.
template <typename ExitFunction>
[[nodiscard]] scope_exit<std::decay_t<ExitFunction>>
make_scope_exit(ExitFunction&& exit_function) noexcept
{
    return scope_exit<std::decay_t<ExitFunction>>(std::forward<ExitFunction>(exit_function));
}

} // namespace stdext
