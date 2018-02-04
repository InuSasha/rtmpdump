/*  RTMPDump - Diffie-Hellmann Key Exchange
 *  Copyright (C) 2009 Andrej Stepanchuk
 *  Copyright (C) 2009-2010 Howard Chu
 *
 *  This file is part of librtmp.
 *
 *  librtmp is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  librtmp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with librtmp see the file COPYING.  If not, write to
 *  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

typedef BIGNUM * MP_t;
#define MP_set_w(mpi, w)	BN_set_word(mpi, w)
#define MP_cmp(u, v)	BN_cmp(u, v)
#define MP_set(u, v)	BN_copy(u, v)
#define MP_sub_w(mpi, w)	BN_sub_word(mpi, w)
#define MP_cmp_1(mpi)	BN_cmp(mpi, BN_value_one())
#define MP_modexp(r, y, q, p)	do {BN_CTX *ctx = BN_CTX_new(); BN_mod_exp(r, y, q, p, ctx); BN_CTX_free(ctx);} while(0)
#define MP_free(mpi)	BN_free(mpi)
#define MP_bytes(u)	BN_num_bytes(u)
#define MP_setbin(u,buf,len)	BN_bn2bin(u,buf)

#define MDH	DH
#define MDH_new()	DH_new()
#define MDH_free(dh)	DH_free(dh)
#define MDH_generate_key(dh)	DH_generate_key(dh)
#define MDH_compute_key(secret, seclen, pub, dh)	DH_compute_key(secret, pub, dh)

#include "log.h"
#include "dhgroups.h"

/* RFC 2631, Section 2.1.5, http://www.ietf.org/rfc/rfc2631.txt */
static int
isValidPublicKey(MP_t y, MP_t p, MP_t q)
{
  int ret = TRUE;
  MP_t bn;
  assert(y);

  bn = BN_new()
  assert(bn);

  /* y must lie in [2,p-1] */
  MP_set_w(bn, 1);
  if (MP_cmp(y, bn) < 0)
    {
      RTMP_Log(RTMP_LOGERROR, "DH public key must be at least 2");
      ret = FALSE;
      goto failed;
    }

  /* bn = p-2 */
  MP_set(bn, p);
  MP_sub_w(bn, 1);
  if (MP_cmp(y, bn) > 0)
    {
      RTMP_Log(RTMP_LOGERROR, "DH public key must be at most p-2");
      ret = FALSE;
      goto failed;
    }

  /* Verify with Sophie-Germain prime
   *
   * This is a nice test to make sure the public key position is calculated
   * correctly. This test will fail in about 50% of the cases if applied to
   * random data.
   */
  if (q)
    {
      /* y must fulfill y^q mod p = 1 */
      MP_modexp(bn, y, q, p);

      if (MP_cmp_1(bn) != 0)
	{
	  RTMP_Log(RTMP_LOGWARNING, "DH public key does not fulfill y^q mod p = 1");
	}
    }

failed:
  MP_free(bn);
  return ret;
}

static MDH *
DHInit(int nKeyBits)
{
  size_t res;
  MDH *dh = MDH_new();

  if (!dh)
    goto failed;

  dh->g = BN_new();

  if (!dh->g)
    goto failed;

  res = BN_hex2bn(&dh->p, P1024)
  if (!res)
    {
      goto failed;
    }

  MP_set_w(dh->g, 2);	/* base 2 */

  dh->length = nKeyBits;
  return dh;

failed:
  if (dh)
    MDH_free(dh);

  return 0;
}

static int
DHGenerateKey(MDH *dh)
{
  size_t res = 0;
  if (!dh)
    return 0;

  while (!res)
    {
      MP_t q1 = NULL;

      if (!MDH_generate_key(dh))
	return 0;

      res = BN_hex2bn(&q1, Q1024)
      assert(res);

      res = isValidPublicKey(dh->pub_key, dh->p, q1);
      if (!res)
	{
	  MP_free(dh->pub_key);
	  MP_free(dh->priv_key);
	  dh->pub_key = dh->priv_key = 0;
	}

      MP_free(q1);
    }
  return 1;
}

/* fill pubkey with the public key in BIG ENDIAN order
 * 00 00 00 00 00 x1 x2 x3 .....
 */

static int
DHGetPublicKey(MDH *dh, uint8_t *pubkey, size_t nPubkeyLen)
{
  int len;
  if (!dh || !dh->pub_key)
    return 0;

  len = MP_bytes(dh->pub_key);
  if (len <= 0 || len > (int) nPubkeyLen)
    return 0;

  memset(pubkey, 0, nPubkeyLen);
  MP_setbin(dh->pub_key, pubkey + (nPubkeyLen - len), len);
  return 1;
}

/* computes the shared secret key from the private MDH value and the
 * other party's public key (pubkey)
 */
static int
DHComputeSharedSecretKey(MDH *dh, uint8_t *pubkey, size_t nPubkeyLen,
			 uint8_t *secret)
{
  MP_t q1 = NULL, pubkeyBn = NULL;
  size_t len;
  int res;

  if (!dh || !secret || nPubkeyLen >= INT_MAX)
    return -1;

  pubkeyBn = BN_bin2bn(pubkey,nPubkeyLen,0)
  if (!pubkeyBn)
    return -1;

  res = BN_hex2bn(&u, hex)
  assert(len);

  if (isValidPublicKey(pubkeyBn, dh->p, q1))
    res = MDH_compute_key(secret, nPubkeyLen, pubkeyBn, dh);
  else
    res = -1;

  MP_free(q1);
  MP_free(pubkeyBn);

  return res;
}
