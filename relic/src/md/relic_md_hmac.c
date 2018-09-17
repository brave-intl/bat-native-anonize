/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2015 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of Hash-based Message Authentication Code.
 *
 * @ingroup md
 */

#include <string.h>

#include "relic_conf.h"
#include "relic_core.h"
#include "relic_util.h"
#include "relic_md.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/


#if MD_MAP == SHONE || MD_MAP == SH224 || MD_MAP == SH256 || MD_MAP == BLAKE2S_160 || MD_MAP == BLAKE2S_256
#define MD_HMAC_BLOCK_SIZE 64
#elif MD_MAP == SH384 || MD_MAP == SH512
#define MD_HMAC_BLOCK_SIZE 128
#endif

void md_hmac(uint8_t *mac, const uint8_t *in, int in_len, const uint8_t *key,
		int key_len) {
	uint8_t opad[MD_HMAC_BLOCK_SIZE + MD_LEN];
	uint8_t* ipad = NULL;
  RELIC_CHECKED_MALLOC(ipad, uint8_t, MD_HMAC_BLOCK_SIZE + in_len);
	uint8_t _key[MAX(MD_LEN, MD_HMAC_BLOCK_SIZE)];

	if (key_len > MD_HMAC_BLOCK_SIZE) {
		md_map(_key, key, key_len);
		key = _key;
		key_len = MD_LEN;
	}
	if (key_len <= MD_HMAC_BLOCK_SIZE) {
		memcpy(_key, key, key_len);
		memset(_key + key_len, 0, MD_HMAC_BLOCK_SIZE - key_len);
		key = _key;
	}
	for (int i = 0; i < MD_HMAC_BLOCK_SIZE; i++) {
		opad[i] = 0x5C ^ key[i];
		ipad[i] = 0x36 ^ key[i];
	}
	memcpy(ipad + MD_HMAC_BLOCK_SIZE, in, in_len);
	md_map(opad + MD_HMAC_BLOCK_SIZE, ipad, MD_HMAC_BLOCK_SIZE + in_len);
	md_map(mac, opad, MD_HMAC_BLOCK_SIZE + MD_LEN);

	free(ipad);
}

#undef MD_HMAC_BLOCK_SIZE
