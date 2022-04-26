// Snark - Wrapper for alt_bn128 add mul pair and modexp

#pragma once

#include <cstdint>
#include <utility>
#include <vector>

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>

namespace fc { namespace snark {
    using bytes = std::vector<char>;
    using Scalar = libff::bigint<libff::alt_bn128_q_limbs>;

    std::pair<int32_t, bytes> alt_bn128_add(bytes _op1, bytes _op2); 
    std::pair<int32_t, bytes> alt_bn128_mul(bytes _g1_point, bytes _scalar);
    std::pair<int32_t, bool>  alt_bn128_pair(bytes _g1_g2_pairs);
    std::pair<int32_t, bytes> modexp(uint32_t _len_base, uint32_t _len_exp, uint32_t _len_modulus, bytes _base, bytes _exponent, bytes _modulus);
    std::pair<int32_t, bytes> blake2f(uint32_t _rounds, bytes _h, bytes _m, bytes _t0_offset, bytes _t1_offset, const char _f);

    enum error_codes : int32_t {
        undefined = -1, ///< undefined error
        none = 0, ///< succeed
        operand_component_invalid,
        operand_at_origin,
        operand_not_in_curve,
        pairing_list_size_error,
        operand_outside_g2,
        modulus_len_zero
    };
} // snark
} // fc
