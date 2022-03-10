#include <fc/crypto/snark.hpp>
#include <libff/common/utils.hpp>

namespace fc { namespace snark {

    std::pair<bool, bytes> alt_bn128_pair(bytes _in) {
        std::pair<bool, bytes> retValue;
        retValue.first = true;
        retValue.second = { 'a' };
        return retValue;
    }

    std::pair<bool, bytes> alt_bn128_add(bytes _in) {
        std::pair<bool, bytes> retValue;
        retValue.first = true;
        retValue.second = { 'a' };
        return retValue;
    }

    std::pair<bool, bytes> alt_bn128_mul(bytes _in) {
        std::pair<bool, bytes> retValue;
        retValue.first = true;
        retValue.second = { 'a' };
        return retValue;
    }

} }