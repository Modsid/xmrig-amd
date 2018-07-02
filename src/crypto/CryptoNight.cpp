/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2016-2018 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 * Copyright 2018      Team-Hycon  <https://github.com/Team-Hycon>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#include <assert.h>


#include "common/net/Job.h"
#include "common/utils/mm_malloc.h"
#include "Cpu.h"
#include "crypto/CryptoNight.h"
#include "crypto/CryptoNight_test.h"
#include "crypto/CryptoNight_x86.h"
#include "net/JobResult.h"
#include "common/net/Protocol.h"


alignas(16) cryptonight_ctx *CryptoNight::m_ctx = nullptr;
xmrig::Algo CryptoNight::m_algorithm = xmrig::CRYPTONIGHT;
xmrig::AlgoVerify CryptoNight::m_av  = xmrig::VERIFY_HW_AES;


bool CryptoNight::hash(const Job &job, JobResult &result, cryptonight_ctx *ctx)
{
    fn(job.variant())(job.blob(), job.size(), result.result, &ctx);
    uint64_t* hash = reinterpret_cast<uint64_t*>(&result.result);

    return hash[3] < job.target();
}


bool CryptoNight::init(xmrig::Algo algorithm)
{
    m_algorithm = algorithm;
    m_av        = Cpu::hasAES() ? xmrig::VERIFY_HW_AES : xmrig::VERIFY_SOFT_AES;

    const bool valid = selfTest();
    freeCtx(m_ctx);
    m_ctx = nullptr;

    return valid;
}


CryptoNight::cn_hash_fun CryptoNight::fn(xmrig::Algo algorithm, xmrig::AlgoVerify av, xmrig::Variant variant)
{
    using namespace xmrig;

    static const cn_hash_fun func_table[36] = {
        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_0>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_0>,

        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_1>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_1>,

        nullptr, nullptr, // VARIANT_IPBC

        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_XTL>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_XTL>,

        cryptonight_single_hash<CRYPTONIGHT, false, VARIANT_MSR>,
        cryptonight_single_hash<CRYPTONIGHT, true,  VARIANT_MSR>,

        nullptr, nullptr, // VARIANT_XHV

#       ifndef XMRIG_NO_AEON
        cryptonight_single_hash<CRYPTONIGHT_LITE, false, VARIANT_0>,
        cryptonight_single_hash<CRYPTONIGHT_LITE, true,  VARIANT_0>,

        cryptonight_single_hash<CRYPTONIGHT_LITE, false, VARIANT_1>,
        cryptonight_single_hash<CRYPTONIGHT_LITE, true,  VARIANT_1>,

        cryptonight_single_hash<CRYPTONIGHT_LITE, false, VARIANT_IPBC>,
        cryptonight_single_hash<CRYPTONIGHT_LITE, true,  VARIANT_IPBC>,

        nullptr, nullptr, // VARIANT_XTL
        nullptr, nullptr, // VARIANT_MSR
        nullptr, nullptr, // VARIANT_XHV
#       else
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
#       endif

#       ifndef XMRIG_NO_SUMO
        cryptonight_single_hash<CRYPTONIGHT_HEAVY, false, VARIANT_0>,
        cryptonight_single_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_0>,

        nullptr, nullptr, // VARIANT_1
        nullptr, nullptr, // VARIANT_IPBC
        nullptr, nullptr, // VARIANT_XTL
        nullptr, nullptr, // VARIANT_MSR

        cryptonight_single_hash<CRYPTONIGHT_HEAVY, false, VARIANT_XHV>,
        cryptonight_single_hash<CRYPTONIGHT_HEAVY, true,  VARIANT_XHV>,
#       else
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr,
#       endif
    };

    const size_t index = VARIANT_MAX * 2 * algorithm + 2 * variant + av - 1;

#   ifndef NDEBUG
    cn_hash_fun func = func_table[index];

    assert(index < sizeof(func_table) / sizeof(func_table[0]));
    assert(func != nullptr);

    return func;
#   else
    return func_table[index];
#   endif
}


cryptonight_ctx *CryptoNight::createCtx(xmrig::Algo algorithm)
{
    cryptonight_ctx *ctx = static_cast<cryptonight_ctx *>(_mm_malloc(sizeof(cryptonight_ctx), 16));
    ctx->memory          = static_cast<uint8_t *>(_mm_malloc(xmrig::cn_select_memory(algorithm), 16));

    return ctx;
}


void CryptoNight::freeCtx(cryptonight_ctx *ctx)
{
    _mm_free(ctx->memory);
    _mm_free(ctx);
}


bool CryptoNight::selfTest() {
    m_ctx = createCtx(m_algorithm);

    if (m_algorithm == xmrig::CRYPTONIGHT) {
        return verify(xmrig::VARIANT_0,   test_output_v0) &&
               verify(xmrig::VARIANT_1,   test_output_v1) &&
               verify(xmrig::VARIANT_XTL, test_output_xtl) &&
               verify(xmrig::VARIANT_MSR, test_output_msr);
    }

#   ifndef XMRIG_NO_AEON
    if (m_algorithm == xmrig::CRYPTONIGHT_LITE) {
        return verify(xmrig::VARIANT_0,    test_output_v0_lite) &&
               verify(xmrig::VARIANT_1,    test_output_v1_lite) &&
               verify(xmrig::VARIANT_IPBC, test_output_ipbc_lite);
    }
#   endif

#   ifndef XMRIG_NO_SUMO
    if (m_algorithm == xmrig::CRYPTONIGHT_HEAVY) {
        return verify(xmrig::VARIANT_0,   test_output_v0_heavy) &&
               verify(xmrig::VARIANT_XHV, test_output_xhv_heavy);
    }
#   endif

    return false;
}


bool CryptoNight::verify(xmrig::Variant variant, const uint8_t *referenceValue)
{
    if (!m_ctx) {
        return false;
    }

    uint8_t output[32];

    cn_hash_fun func = fn(variant);
    if (!func) {
        return false;
    }

    func(test_input, 76, output, &m_ctx);

    return memcmp(output, referenceValue, 32) == 0;
}
