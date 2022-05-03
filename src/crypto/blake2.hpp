/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <functional>

namespace fc {

class Blake2bWrapper {
public:
    enum blake2b_constant { BLAKE2B_BLOCKBYTES = 128 };

    typedef struct blake2b_state__ {
        uint64_t h[8];
        uint64_t t[2];
        uint64_t f[2];
    } blake2b_state;

    void blake2b_compress(blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES], size_t r, const std::function<bool(int)> &callBackFun );
   
private:
    uint64_t m[16];
    uint64_t v[16];
    size_t i;

    void blake2b_compress_init(blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES], size_t r);
    void blake2b_compress_end(blake2b_state *S);
};

}