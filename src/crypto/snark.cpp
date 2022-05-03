#include <fc/crypto/snark.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/profiling.hpp>
#include <boost/throw_exception.hpp>
#include <algorithm>
#include "blake2.h"

namespace fc { namespace snark {

    void initLibSnark() noexcept {
        static bool s_initialized = []() noexcept {
            libff::inhibit_profiling_info = true;
            libff::inhibit_profiling_counters = true;
            libff::alt_bn128_pp::init_public_params();
            return true; 
        }();
        (void)s_initialized;
    }

    Scalar to_scalar(bytes be) noexcept {
        mpz_t m;
        mpz_init(m);
        mpz_import(m, be.size(), /*order=*/1, /*size=*/1, /*endian=*/0, /*nails=*/0, &be[0]);
        Scalar out{m};
        mpz_clear(m);
        return out;
    }

    // Notation warning: Yellow Paper's p is the same libff's q.
    // Returns x < p (YP notation).
    static bool valid_element_of_fp(const Scalar& x) noexcept {
        return mpn_cmp(x.data, libff::alt_bn128_modulus_q.data, libff::alt_bn128_q_limbs) < 0;
    }

    std::pair<int32_t, libff::alt_bn128_G1> decode_g1_element(bytes bytes64_be) noexcept {
        assert(bytes64_be.size() == 64);
    
        bytes sub1(bytes64_be.begin(), bytes64_be.begin()+32);
        bytes sub2(bytes64_be.begin()+32, bytes64_be.begin()+64);

        Scalar x{to_scalar(sub1)};
        if (!valid_element_of_fp(x)) {
            return std::make_pair(error_codes::operand_component_invalid, libff::alt_bn128_G1::zero());
        }

        Scalar y{to_scalar(sub2)};
        if (!valid_element_of_fp(y)) {
            return std::make_pair(error_codes::operand_component_invalid, libff::alt_bn128_G1::zero());
        }

        if (x.is_zero() && y.is_zero()) {
            return std::make_pair(error_codes::operand_at_origin, libff::alt_bn128_G1::zero());
        }

        libff::alt_bn128_G1 point{x, y, libff::alt_bn128_Fq::one()};
        if (!point.is_well_formed()) {
            return std::make_pair(error_codes::operand_not_in_curve, libff::alt_bn128_G1::zero());
        }
        return std::make_pair(error_codes::none, point);
    }

    std::pair<int32_t, libff::alt_bn128_Fq2> decode_fp2_element(bytes bytes64_be) noexcept {
        assert(bytes64_be.size() == 64);

       // big-endian encoding
        bytes sub1(bytes64_be.begin()+32, bytes64_be.begin()+64);
        bytes sub2(bytes64_be.begin(), bytes64_be.begin()+32);        

        Scalar c0{to_scalar(sub1)};
        Scalar c1{to_scalar(sub2)};

        if (!valid_element_of_fp(c0) || !valid_element_of_fp(c1)) {
            return std::make_pair(error_codes::operand_component_invalid, libff::alt_bn128_Fq2::one() );
        }

        return std::make_pair(error_codes::none, libff::alt_bn128_Fq2{c0, c1});
    }

    std::pair<int32_t, libff::alt_bn128_G2> decode_g2_element(bytes bytes128_be) noexcept {
        assert(bytes128_be.size() == 128);

        bytes sub1(bytes128_be.begin(), bytes128_be.begin()+64);        
        auto x = decode_fp2_element(sub1);
        if (x.first) {
            return std::make_pair(x.first, libff::alt_bn128_G2::zero());
        }

        bytes sub2(bytes128_be.begin()+64, bytes128_be.begin()+128);        
        auto y = decode_fp2_element(sub2);
        
        if (y.first) {
            return std::make_pair(y.first, libff::alt_bn128_G2::zero());
        }

        if (x.second.is_zero() && y.second.is_zero()) {
            return std::make_pair(error_codes::operand_at_origin, libff::alt_bn128_G2::zero());
        }

        libff::alt_bn128_G2 point{x.second, y.second, libff::alt_bn128_Fq2::one()};
        if (!point.is_well_formed()) {
            return std::make_pair(error_codes::operand_not_in_curve, libff::alt_bn128_G2::zero());;
        }

        if (!(libff::alt_bn128_G2::order() * point).is_zero()) {
            // wrong order, doesn't belong to the subgroup G2
            return std::make_pair(error_codes::operand_outside_g2, libff::alt_bn128_G2::zero());;
        }

        return std::make_pair(error_codes::none, point);
    }

    bytes encode_g1_element(libff::alt_bn128_G1 p) noexcept {
        bytes out(64, '\0');
        if (p.is_zero()) {
            return out;
        }

        p.to_affine_coordinates();

        auto x{p.X.as_bigint()};
        auto y{p.Y.as_bigint()};

        std::memcpy(&out[0], y.data, 32);
        std::memcpy(&out[32], x.data, 32);

        std::reverse(out.begin(), out.end());
        return out;
    }

    std::pair<int32_t, bytes> alt_bn128_add(bytes _op1, bytes _op2) {
        bytes buffer;

        snark::initLibSnark();

        auto x = snark::decode_g1_element(_op1);

        if (x.first != error_codes::none) {
            return std::make_pair(x.first, buffer);
        }

        auto y = snark::decode_g1_element(_op2);

        if (y.first != error_codes::none) {
            return std::make_pair(y.first, buffer);
        }

        libff::alt_bn128_G1 g1Sum = x.second + y.second;
        auto retEncoded = snark::encode_g1_element(g1Sum);
        return std::make_pair(error_codes::none, retEncoded);
    }

    std::pair<int32_t, bytes> alt_bn128_mul(bytes _g1_point, bytes _scalar) {
        bytes buffer;

        snark::initLibSnark();

        auto x = snark::decode_g1_element(_g1_point);

        if (x.first) {
            return std::make_pair(x.first, buffer);
        }

        snark::Scalar n{snark::to_scalar(_scalar)};

        libff::alt_bn128_G1 g1Product = n * x.second;
        auto retEncoded = snark::encode_g1_element(g1Product);
        return std::make_pair(0, retEncoded);
    }
    
    static constexpr size_t kSnarkvStride{192};

    std::pair<int32_t, bool>  alt_bn128_pair(bytes _g1_g2_pairs) {
        if (_g1_g2_pairs.size() % kSnarkvStride != 0) {
            return std::make_pair(error_codes::pairing_list_size_error, false);
        }

        size_t k{_g1_g2_pairs.size() / kSnarkvStride};

        snark::initLibSnark();
        using namespace libff;

        static const auto one{alt_bn128_Fq12::one()};
        auto accumulator{one};

        for (size_t i{0}; i < k; ++i) {
            auto offset = i * kSnarkvStride;
            bytes sub1(_g1_g2_pairs.begin()+offset, _g1_g2_pairs.begin()+offset+64);        
            auto a = snark::decode_g1_element(sub1);
            if (a.first) {
                return std::make_pair(a.first, false);
            }
            bytes sub2(_g1_g2_pairs.begin()+offset+64, _g1_g2_pairs.begin()+offset+64+128);        
            auto b = snark::decode_g2_element(sub2);
            if (b.first) {
                return std::make_pair(b.first, false);
            }

            if (a.second.is_zero() || b.second.is_zero()) {
                continue;
            }

            accumulator = accumulator * alt_bn128_miller_loop(alt_bn128_precompute_G1(a.second), alt_bn128_precompute_G2(b.second));
        }

        bool pair_result = false;
        if (alt_bn128_final_exponentiation(accumulator) == one) {
            pair_result = true;
        }
               
        return std::make_pair(0, pair_result);
    }

    std::pair<int32_t, bytes> modexp(uint32_t _len_base, uint32_t _len_exp, uint32_t _len_modulus, bytes _base, bytes _exponent, bytes _modulus) 
    {
        auto output = bytes(_len_modulus, '\0');

        if (_len_modulus == 0) {
            return std::make_pair(error_codes::modulus_len_zero, output);
        }

        mpz_t base;
        mpz_init(base);
        if (_len_base) {
            auto basePtr = static_cast<void*>(_base.data());
            mpz_import(base, _len_base, 1, 1, 0, 0, basePtr);
        }

        mpz_t exponent;
        mpz_init(exponent);
        if (_len_exp) {
            auto expPtr = static_cast<void*>(_exponent.data());
            mpz_import(exponent, _len_exp, 1, 1, 0, 0, expPtr);
        }

        mpz_t modulus;
        mpz_init(modulus);
        auto modPtr = static_cast<void*>(_modulus.data());
        mpz_import(modulus, _len_modulus, 1, 1, 0, 0, modPtr);

        if (mpz_sgn(modulus) == 0) {
            mpz_clear(modulus);
            mpz_clear(exponent);
            mpz_clear(base);

            return std::make_pair(error_codes::none, output);
        }

        mpz_t result;
        mpz_init(result);

        mpz_powm(result, base, exponent, modulus);
        // export as little-endian
        mpz_export(static_cast<void*>(output.data()), nullptr, -1, 1, 0, 0, result);
        // and convert to big-endian
        std::reverse(output.begin(), output.end());

        mpz_clear(result);
        mpz_clear(modulus);
        mpz_clear(exponent);
        mpz_clear(base);

        return std::make_pair(error_codes::none, output);
    }

    std::pair<int32_t, bytes> blake2f(uint32_t _rounds, bytes _h, bytes _m, bytes _t0_offset, bytes _t1_offset, bool _f) {
        blake2b_state state{};
        bytes out(sizeof(state.h), 0);

        //  EIP-152 [4 bytes for rounds][64 bytes for h][128 bytes for m][8 bytes for t_0][8 bytes for t_1][1 byte for f] : 213
        //          [------------------][64 bytes for h][128 bytes for m][8 bytes for t_0][8 bytes for t_1][------------] : 208
        //  * rounds and final indicator flag are not serialized
        if (_h.size() + _m.size() + _t0_offset.size() + _t1_offset.size() != 208 ) {
            return std::make_pair(error_codes::input_len_error, out);
        }
   
        memset(&state, 0, sizeof(blake2b_state));

        memcpy(state.h, _h.data(), 64);

        // final indicator flag set words to 1's if true
        state.f[0] = _f?std::numeric_limits<uint64_t>::max():0;

        memcpy(&state.t[0], _t0_offset.data(), 8);
        memcpy(&state.t[1], _t1_offset.data(), 8);

        uint8_t block[128];
        memcpy(block, _m.data(), 128);
        
        blake2b_compress(&state, block, _rounds);

        std::memcpy(&out[0], &state.h[0], out.size());

        return std::make_pair(error_codes::none, out);
    }
}
}
