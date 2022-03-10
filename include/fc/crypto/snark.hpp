// Snark - Wrapper for alt_bn128 add mul pair and modexp

#pragma once

#include <utility>
#include <vector>

using byte = unsigned char;
using bytes = std::vector<byte>;


namespace fc { namespace snark {
/*
    Original : 
    std::pair<bool, bytes> alt_bn128_pairing_product(bytesConstRef _in);
    std::pair<bool, bytes> alt_bn128_G1_add(bytesConstRef _in);
    std::pair<bool, bytes> alt_bn128_G1_mul(bytesConstRef _in);
*/
    std::pair<bool, bytes> alt_bn128_pair(bytes _in);
    std::pair<bool, bytes> alt_bn128_add(bytes _in);
    std::pair<bool, bytes> alt_bn128_mul(bytes _in);

}}