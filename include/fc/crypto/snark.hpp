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
        
    //std::pair<int32_t, bool>  alt_bn128_pair(bytes _g1_pairs, bytes _g2_pairs);

}}
