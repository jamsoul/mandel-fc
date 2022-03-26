// Snark - Wrapper for alt_bn128 add mul pair and modexp

#pragma once

#include <cstdint>
#include <utility>
#include <vector>

namespace fc { namespace snark {
    using fc_span = std::vector<uint8_t>;

    int32_t alt_bn128_pair(fc_span _g1_pairs, fc_span _g2_pairs, bool *result );
    int32_t alt_bn128_add(fc_span _op1, fc_span _op2, fc_span* result);
    int32_t alt_bn128_mul(fc_span _g1_point, fc_span _scalar, fc_span* result);
}}
