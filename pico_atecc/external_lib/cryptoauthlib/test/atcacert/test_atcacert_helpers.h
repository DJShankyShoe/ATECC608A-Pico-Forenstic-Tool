/**
 * \file
 * \brief Test for the Cryptoauthlib Compressed Certficiate API
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

#ifndef TEST_ATCACERT_HELPERS_H
#define TEST_ATCACERT_HELPERS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "atca_test.h"
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
    uint16_t                 ca_slot);
#endif

#ifdef __cplusplus
}
#endif

#endif /* TEST_ATCACERT_HELPERS_H */
