/**
 * \file
 * \brief atcacert tests helper file
 *
 * \copyright (c) 2020-2025 Microchip Technology Inc. and its subsidiaries.
 *
 * \page License
 *
 * Subject to your compliance with these terms, you may use Microchip software
 * and any derivatives exclusively with Microchip products. It is your
 * responsibility to comply with third party license terms applicable to your
 * use of third party software (including open source software) that may
 * accompany Microchip software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
 * SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
 * OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
 * MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
 * FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
 * LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
 * THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
 * THIS SOFTWARE.
 */

#include "atca_test.h"

#ifndef DO_NOT_TEST_CERT
#include "atcacert/atcacert_client.h"

#if ATCACERT_COMPCERT_EN && ATCAC_SHA384_EN && ATCAC_SHA512_EN && ATCA_TA_SUPPORT
void build_and_save_cert_ta(
    const atcacert_def_t* cert_def,
    uint8_t* cert,
    size_t* cert_size,
    const cal_buffer* ca_public_key,
    const cal_buffer* public_key,
    const uint8_t            signer_id[2],
    const atcacert_tm_utc_t* issue_date,
    const uint8_t* sn,
    uint16_t                 ca_slot)
{
    int ret;
    atcacert_build_state_t build_state;
    uint8_t tbs_digest[64];
    cal_buffer tbs_digest_buf = CAL_BUF_INIT(sizeof(tbs_digest), tbs_digest);
    uint8_t signature[ATCA_ECCP521_SIG_SIZE];
    cal_buffer sig = CAL_BUF_INIT(sizeof(signature), signature);
    uint8_t comp_cert[ATCACERT_COMP_CERT_MAX_SIZE];
    size_t max_cert_size = *cert_size;

    atcacert_tm_utc_t expire_date = {
        .tm_year = issue_date->tm_year + cert_def->expire_years,
        .tm_mon = issue_date->tm_mon,
        .tm_mday = issue_date->tm_mday,
        .tm_hour = issue_date->tm_hour,
        .tm_min = 0,
        .tm_sec = 0
    };

    const atcacert_device_loc_t dedicated_data_dev_loc = {
        .zone = DEVZONE_DEDICATED_DATA,
        .offset = 0,
        .count = 8u
    };

    atcacert_device_loc_t device_locs[4];
    size_t device_locs_count = 0;
    size_t i;

    if (cert_def->expire_years == 0)
    {
        ret = atcacert_date_get_max_date(cert_def->expire_date_format, &expire_date);
        TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    }

    ret = atcacert_cert_build_start(atcab_get_device(), &build_state, cert_def, cert, cert_size, ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_set_subj_public_key(build_state.cert_def, build_state.cert, *build_state.cert_size, public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    ret = atcacert_set_issue_date(build_state.cert_def, build_state.cert, *build_state.cert_size, issue_date);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    ret = atcacert_set_expire_date(build_state.cert_def, build_state.cert, *build_state.cert_size, &expire_date);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    ret = atcacert_set_signer_id(build_state.cert_def, build_state.cert, *build_state.cert_size, signer_id);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    ret = atcacert_get_comp_cert(build_state.cert_def, build_state.cert, *build_state.cert_size, comp_cert);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_cert_build_process(&build_state, &dedicated_data_dev_loc, sn);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_cert_build_process(&build_state, &cert_def->comp_cert_dev_loc, comp_cert);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_cert_build_finish(&build_state);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_get_tbs_digest(build_state.cert_def, build_state.cert, *build_state.cert_size, &tbs_digest_buf);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = talib_sign_external(atcab_get_device(), TA_KEY_TYPE_ECCP521, ca_slot, TA_HANDLE_INPUT_BUFFER,
                              &tbs_digest_buf, &sig);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcacert_set_signature(cert_def, cert, cert_size, max_cert_size, &sig);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_get_device_locs(atcab_get_device(), cert_def, device_locs, &device_locs_count, sizeof(device_locs) / sizeof(device_locs[0]), 32);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    for (i = 0; i < device_locs_count; i++)
    {
        uint8_t data[1024];

        if (device_locs[i].zone == DEVZONE_CONFIG || device_locs[i].zone == DEVZONE_DEDICATED_DATA)
        {
            continue;
        }
        if (device_locs[i].zone == DEVZONE_DATA && device_locs[i].is_genkey)
        {
            continue;
        }

        TEST_ASSERT(sizeof(data) >= device_locs[i].count);

        ret = atcacert_get_device_data(cert_def, cert, *cert_size, &device_locs[i], data);
        TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

        ret = talib_write_bytes_zone(atcab_get_device(), device_locs[i].zone, device_locs[i].slot, device_locs[i].offset, data, device_locs[i].count);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    }
}
#endif /* ATCACERT_COMPCERT_EN && ATCAC_SHA384_EN && ATCAC_SHA512_EN && ATCA_TA_SUPPORT */
#endif /* DO_NOT_TEST_CERT */