#include <fc/crypto/snark.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/profiling.hpp>
#include <boost/throw_exception.hpp>

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
            return std::make_pair(1, libff::alt_bn128_G1::zero());
        }

        Scalar y{to_scalar(sub2)};
        if (!valid_element_of_fp(y)) {
            return std::make_pair(1, libff::alt_bn128_G1::zero());
        }

        if (x.is_zero() && y.is_zero()) {
            return std::make_pair(1, libff::alt_bn128_G1::zero());
        }

        libff::alt_bn128_G1 point{x, y, libff::alt_bn128_Fq::one()};
        if (!point.is_well_formed()) {
            return std::make_pair(1, libff::alt_bn128_G1::zero());
        }
        return std::make_pair(0, point);
    }

    std::pair<int32_t, libff::alt_bn128_Fq2> decode_fp2_element(bytes bytes64_be) noexcept {
        assert(bytes64_be.size() == 64);

       // big-endian encoding
        bytes sub1(bytes64_be.begin()+32, bytes64_be.begin()+64);
        bytes sub2(bytes64_be.begin(), bytes64_be.begin()+32);        

        Scalar c0{to_scalar(sub1)};
        Scalar c1{to_scalar(sub2)};

        if (!valid_element_of_fp(c0) || !valid_element_of_fp(c1)) {
            return {};
        }

        return std::make_pair(0, libff::alt_bn128_Fq2{c0, c1});
    }

    std::pair<int32_t, libff::alt_bn128_G2> decode_g2_element(bytes bytes128_be) noexcept {
        assert(bytes128_be.size() == 128);

        bytes sub1(bytes128_be.begin(), bytes128_be.begin()+64);        
        auto x = decode_fp2_element(sub1);
        if (x.first) {
            return std::make_pair(1, libff::alt_bn128_G2::zero());
        }

        bytes sub2(bytes128_be.begin()+64, bytes128_be.begin()+128);        
        auto y = decode_fp2_element(sub2);
        
        if (y.first) {
            return std::make_pair(1, libff::alt_bn128_G2::zero());
        }

        if (x.second.is_zero() && y.second.is_zero()) {
            return std::make_pair(0, libff::alt_bn128_G2::zero());
        }

        libff::alt_bn128_G2 point{x.second, y.second, libff::alt_bn128_Fq2::one()};
        if (!point.is_well_formed()) {
            return std::make_pair(1, libff::alt_bn128_G2::zero());;
        }

        if (!(libff::alt_bn128_G2::order() * point).is_zero()) {
            // wrong order, doesn't belong to the subgroup G2
            return std::make_pair(1, libff::alt_bn128_G2::zero());;
        }

        return std::make_pair(0, point);
    }

    bytes encode_g1_element(libff::alt_bn128_G1 p) noexcept {
        bytes out(64, '\0');
        if (p.is_zero()) {
            return out;
        }

        p.to_affine_coordinates();

        auto x{p.X.as_bigint()};
        auto y{p.Y.as_bigint()};

//        // Here we convert little-endian data to big-endian output
//        static_assert(SILKWORM_BYTE_ORDER == SILKWORM_LITTLE_ENDIAN);
//        static_assert(sizeof(x.data) == 32);

        std::memcpy(&out[0], y.data, 32);
        std::memcpy(&out[32], x.data, 32);

//        std::reverse(out.begin(), out.end());
        return out;
    }

    std::pair<int32_t, bytes> alt_bn128_add(bytes _op1, bytes _op2) {
        bytes buffer;

        snark::initLibSnark();

        auto x = snark::decode_g1_element(_op1);

        if (x.first) {
            return std::make_pair(1, buffer);
        }

        auto y = snark::decode_g1_element(_op2);

        if (y.first) {
            return std::make_pair(1, buffer);
        }

        libff::alt_bn128_G1 g1Sum = x.second + y.second;
        auto retEncoded = snark::encode_g1_element(g1Sum);
        return std::make_pair(0, retEncoded);
    }

    std::pair<int32_t, bytes> alt_bn128_mul(bytes _g1_point, bytes _scalar) {
        bytes buffer;

        snark::initLibSnark();

        auto x = snark::decode_g1_element(_g1_point);

        if (x.first) {
            return std::make_pair(1, buffer);
        }

        snark::Scalar n{snark::to_scalar(_scalar)};

        libff::alt_bn128_G1 g1Product = n * x.second;
        auto retEncoded = snark::encode_g1_element(g1Product);
        return std::make_pair(0, retEncoded);
    }
    
    //std::pair<int32_t, bool>  alt_bn128_pair(bytes _g1_pairs, bytes _g2_pairs) {}
}
}