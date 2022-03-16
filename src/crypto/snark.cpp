#include <fc/crypto/snark.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g2.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/profiling.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/throw_exception.hpp>



namespace fc { namespace snark {

    using u256 =  boost::multiprecision::number<boost::multiprecision::cpp_int_backend<256, 256, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked, void>>;

    /// Concatenate the contents of a container onto a vector
    template <class T, class U> std::vector<T> operator+(std::vector<T> _a, U const& _b)
    {
        return _a += _b;
    }

    class h256 {
    public:
        enum ConstructFromHashType { AlignLeft, AlignRight, FailIfDifferent };

        std::array<byte, 32> m_data;
        // @returns a particular byte from the hash.
        byte& operator[](unsigned _i) { return m_data[_i]; }
        // @returns a particular byte from the hash.
        byte operator[](unsigned _i) const { return m_data[_i]; }
        /// Explicitly construct, copying from a byte array.
        explicit h256(bytes const& _b, ConstructFromHashType _t = FailIfDifferent) { if (_b.size() == 32) memcpy(m_data.data(), _b.data(), std::min<unsigned>(_b.size(), 32)); else { m_data.fill(0); if (_t != FailIfDifferent) { auto c = std::min<unsigned>(_b.size(), 32); for (unsigned i = 0; i < c; ++i) m_data[_t == AlignRight ? 32 - 1 - i : i] = _b[_t == AlignRight ? _b.size() - 1 - i : i]; } } }
        /// Explicitly construct, copying from a byte array.
        explicit h256(bytesConstRef _b, ConstructFromHashType _t = FailIfDifferent) { if (_b.size() == 32) memcpy(m_data.data(), _b.data(), std::min<unsigned>(_b.size(), 32)); else { m_data.fill(0); if (_t != FailIfDifferent) { auto c = std::min<unsigned>(_b.size(), 32); for (unsigned i = 0; i < c; ++i) m_data[_t == AlignRight ? 32 - 1 - i : i] = _b[_t == AlignRight ? _b.size() - 1 - i : i]; } } }
        /// @returns a mutable byte pointer to the object's data.
        byte* data() { return m_data.data(); }
        /// @returns a constant byte pointer to the object's data.
        byte const* data() const { return m_data.data(); }
        /// @returns a copy of the object's data as a byte vector.
        bytes asBytes() const { return bytes(data(), data() + 32); }

        h256() { m_data.fill(0); }


    };

    void initLibSnark() noexcept {
        static bool s_initialized = []() noexcept {
            libff::inhibit_profiling_info = true;
            libff::inhibit_profiling_counters = true;
            libff::alt_bn128_pp::init_public_params();
            return true;
        }();
        (void)s_initialized;
    }

    libff::bigint<libff::alt_bn128_q_limbs> toLibsnarkBigint(h256 const& _x) {
        libff::bigint<libff::alt_bn128_q_limbs> b;
        auto const N = b.N;
        constexpr size_t L = sizeof(b.data[0]);
        static_assert(sizeof(mp_limb_t) == L, "Unexpected limb size in libff::bigint.");
        for (size_t i = 0; i < N; i++)
            for (size_t j = 0; j < L; j++)
                b.data[N - 1 - i] |= mp_limb_t(_x[i * L + j]) << (8 * (L - 1 - j));
        return b;
    }

    h256 fromLibsnarkBigint(libff::bigint<libff::alt_bn128_q_limbs> const& _b) {
        static size_t const N = static_cast<size_t>(_b.N);
        static size_t const L = sizeof(_b.data[0]);
        static_assert(sizeof(mp_limb_t) == L, "Unexpected limb size in libff::bigint.");
        h256 x;
        for (size_t i = 0; i < N; i++)
            for (size_t j = 0; j < L; j++)
                x[i * L + j] = uint8_t(_b.data[N - 1 - i] >> (8 * (L - 1 - j)));
        return x;
    }

    libff::alt_bn128_Fq decodeFqElement(bytesConstRef _data) {
        // h256::AlignLeft ensures that the h256 is zero-filled on the right if _data
        // is too short.
        h256 xbin(_data, h256::AlignLeft);
        // TODO: Consider using a compiler time constant for comparison.
     //   if (u256(xbin) >= u256(fromLibsnarkBigint(libff::alt_bn128_Fq::mod)))
     //       BOOST_THROW_EXCEPTION(InvalidEncoding());
        return toLibsnarkBigint(xbin);
    }

    libff::alt_bn128_G1 decodePointG1(bytesConstRef _data) {
        libff::alt_bn128_Fq x = decodeFqElement(_data.cropped(0));
        libff::alt_bn128_Fq y = decodeFqElement(_data.cropped(32));
        if (x == libff::alt_bn128_Fq::zero() && y == libff::alt_bn128_Fq::zero())
            return libff::alt_bn128_G1::zero();
        libff::alt_bn128_G1 p(x, y, libff::alt_bn128_Fq::one());
     //   if (!p.is_well_formed())
       //     BOOST_THROW_EXCEPTION(InvalidEncoding());
        return p;
    }


    bytes encodePointG1(libff::alt_bn128_G1 _p) {
        if (_p.is_zero())
            return bytes(64, 0);
        _p.to_affine_coordinates();
        
        auto retValue = fromLibsnarkBigint(_p.X.as_bigint()).asBytes();
        auto retValue2 = fromLibsnarkBigint(_p.Y.as_bigint()).asBytes();
        retValue.insert( retValue.end(), retValue2.begin(), retValue2.end());
        return retValue;            
    }

    libff::alt_bn128_Fq2 decodeFq2Element(bytesConstRef _data) {
        // Encoding: c1 (256 bits) c0 (256 bits)
        // "Big endian", just like the numbers
        return libff::alt_bn128_Fq2(
            decodeFqElement(_data.cropped(32)),
            decodeFqElement(_data.cropped(0))
        );
    }

    libff::alt_bn128_G2 decodePointG2(bytesConstRef _data) {
        libff::alt_bn128_Fq2 const x = decodeFq2Element(_data);
        libff::alt_bn128_Fq2 const y = decodeFq2Element(_data.cropped(64));
        if (x == libff::alt_bn128_Fq2::zero() && y == libff::alt_bn128_Fq2::zero())
            return libff::alt_bn128_G2::zero();
        libff::alt_bn128_G2 p(x, y, libff::alt_bn128_Fq2::one());
        //if (!p.is_well_formed())
          //  BOOST_THROW_EXCEPTION(InvalidEncoding());
        return p;
    }

    std::pair<bool, bytes> alt_bn128_pair(bytesConstRef _in) {
        size_t constexpr pairSize = 2 * 32 + 2 * 64;
        size_t const pairs = _in.size() / pairSize;
        if (pairs * pairSize != _in.size()) // Invalid length.
            return {false, bytes{}};

        initLibSnark();
        libff::alt_bn128_Fq12 x = libff::alt_bn128_Fq12::one();
        for (size_t i = 0; i < pairs; ++i) {
            bytesConstRef const pair = _in.cropped(i * pairSize, pairSize);
            libff::alt_bn128_G1 const g1 = decodePointG1(pair);
            libff::alt_bn128_G2 const p = decodePointG2(pair.cropped(2 * 32));
            if (-libff::alt_bn128_G2::scalar_field::one() * p + p != libff::alt_bn128_G2::zero())
                // p is not an element of the group (has wrong order)
                return {false, bytes()};
            if (p.is_zero() || g1.is_zero())
                continue; // the pairing is one
            x = x * libff::alt_bn128_miller_loop(
                libff::alt_bn128_precompute_G1(g1),
                libff::alt_bn128_precompute_G2(p)
            );
        }

        bool const result = libff::alt_bn128_final_exponentiation(x) == libff::alt_bn128_GT::one();

        std::pair<bool, bytes> retValue;
        return retValue;
    }

    std::pair<bool, bytes> alt_bn128_add(bytesConstRef _in) {
    /*  
        std::pair<bool, bytes> retValue;
        retValue.first = true;
        retValue.second = { 'a' };
        return retValue;
    */
        initLibSnark();
        libff::alt_bn128_G1 const p1 = decodePointG1(_in);
        libff::alt_bn128_G1 const p2 = decodePointG1(_in.cropped(32 * 2));
        return {true, encodePointG1(p1 + p2)};
    }

    std::pair<bool, bytes> alt_bn128_mul(bytesConstRef _in) {
		initLibSnark();
		libff::alt_bn128_G1 const p = decodePointG1(_in.cropped(0));
		libff::alt_bn128_G1 const result = toLibsnarkBigint(h256(_in.cropped(64), h256::AlignLeft)) * p;
		return {true, encodePointG1(result)};    }

} }