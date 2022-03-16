// Snark - Wrapper for alt_bn128 add mul pair and modexp

#pragma once

#include <utility>
#include <vector>
#include <fc/vector_ref.hpp>

namespace fc { namespace snark {
    using byte = unsigned char;
    using bytes = std::vector<byte>;
    using bytesRef = vector_ref<byte>;
    using bytesConstRef = vector_ref<byte const>;

    std::pair<bool, bytes> alt_bn128_pair(bytesConstRef _in);
    std::pair<bool, bytes> alt_bn128_add(bytesConstRef _in);
    std::pair<bool, bytes> alt_bn128_mul(bytesConstRef _in);
}}