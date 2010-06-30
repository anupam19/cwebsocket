/*
 * Copyright (c) 2010 Putilov Andrey
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "websocket.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 1
#endif

static void
md5(char *out_md5, const unsigned char *in_buf, size_t in_len);

void nullhandshake(struct handshake *hs)
{
	hs->host = NULL;
	hs->key1 = NULL;
	hs->key2 = NULL;
	hs->origin = NULL;
	hs->protocol = NULL;
	hs->resource = NULL;
}

static uint32_t doStuffToObtainAnInt32(const char *key)
{
    char res_decimals[50] = "";
    char *tail_res = res_decimals;
    uint8_t space_count = 0;
    uint8_t i=0;
    do {
        if (isdigit(key[i]))
            strncat(tail_res++, &key[i], 1);
        if (key[i] == ' ')
            space_count++;
    } while (key[++i]);
    tail_res = 0;

    return  ((uint32_t)atol(res_decimals) / space_count);
}

static char* get_upto_linefeed(const char *start_from)
{
	char *write_to;
	uint8_t new_length = strstr(start_from, "\r\n") - start_from + 1;
	write_to = malloc(new_length); //+1 for '\x00'
	memcpy(write_to, start_from, new_length-1);
	write_to[ new_length-1 ] = 0;

	return write_to;
}

enum ws_frame_type ws_parse_handshake(const char *input_frame, size_t input_len,
	struct handshake *hs)
{
	const char *input_ptr = input_frame;
	const char *end_ptr = input_frame + input_len;

	// measure resource size
	char *first = strchr(input_frame, ' ');
	if (!first)
		return WS_ERROR_FRAME;
	first++;
	char *second = strchr(first, ' ');
	if (!second)
		return WS_ERROR_FRAME;

	if (hs->resource) {
		free(hs->resource);
		hs->resource = NULL;
	}
	hs->resource = malloc(second-first + 1); // +1 is for \x00 symbol
	assert(hs->resource);

	if (sscanf(input_ptr, "GET %s HTTP/1.1\r\n", hs->resource) != 1)
		return WS_ERROR_FRAME;
	input_ptr = strstr(input_ptr, "\r\n") + 2;

	/*
		parse next lines
	*/
	#define input_ptr_len (input_len - (input_ptr-input_frame))
	#define prepare(x) do {if (x) { free(x); x = NULL; }} while(0)
	const char connection[] =  "Connection: Upgrade";
	const char upgrade[] =  "Upgrade: WebSocket";
	const char host[] =  "Host: ";
	const char origin[] =  "Origin: ";
	const char protocol[] =  "Sec-WebSocket-Protocol: ";
	const char key1[] =  "Sec-WebSocket-Key1: ";
	const char key2[] =  "Sec-WebSocket-Key2: ";
	uint8_t connection_flag = FALSE;
	uint8_t upgrade_flag = FALSE;
	while (input_ptr < end_ptr && input_ptr[0] != '\r' && input_ptr[1] != '\n') {
		if ( memcmp(input_ptr, host, strlen(host)) == 0 ) {
			input_ptr+= strlen(host);
			prepare(hs->host);
			hs->host = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp(input_ptr, origin, strlen(origin)) == 0 ) {
			input_ptr+= strlen(origin);
			prepare(hs->origin);
			hs->origin = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp(input_ptr, protocol, strlen(protocol)) == 0 ) {
			input_ptr+= strlen(protocol);
			prepare(hs->protocol);
			hs->protocol = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp(input_ptr, key1, strlen(key1)) == 0 ) {
			input_ptr+= strlen(key1);
			prepare(hs->key1);
			hs->key1 = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp(input_ptr, key2, strlen(key2)) == 0 ) {
			input_ptr+= strlen(key2);
			prepare(hs->key2);
			hs->key2 = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp(input_ptr, connection, strlen(connection)) == 0 ) {
			connection_flag = TRUE;
		} else
		if ( memcmp(input_ptr, upgrade, strlen(upgrade)) == 0 ) {
			upgrade_flag = TRUE;
		};

		input_ptr = strstr(input_ptr, "\r\n") + 2;
	}

	// we have read all data, so check them
	if (!hs->host || !hs->origin || !hs->key1 || !hs->key2 ||
			!connection_flag || !upgrade_flag)
		return WS_ERROR_FRAME;

	input_ptr+=2; // skip empty line
	if (end_ptr - input_ptr < 8)
		return WS_INCOMPLETE_FRAME;
	memcpy(hs->key3, input_ptr, 8);

	return WS_OPENING_FRAME;
}

enum ws_frame_type ws_get_handshake_answer(const struct handshake *hs,
	char *out_frame, size_t *out_len)
{
	assert(out_len && *out_len);
	assert(out_frame);
	// hs->key3 is always not NULL
	assert(hs && hs->origin && hs->host && hs->resource && hs->key1 && hs->key2);

    char chrkey1[4];
    char chrkey2[4];
    uint32_t key1 = doStuffToObtainAnInt32(hs->key1);
    uint32_t key2 = doStuffToObtainAnInt32(hs->key2);
    uint8_t i;
    for (i=0; i<4; i++)
        chrkey1[i] = key1<<(8*i)>>(8*3);
    for (i=0; i<4; i++)
        chrkey2[i] = key2<<(8*i)>>(8*3);

	unsigned char raw_md5[16];
    char keys[16];
    memcpy(keys, chrkey1, 4);
    memcpy(&keys[4], chrkey2, 4);
    memcpy(&keys[8], hs->key3, 8);
	md5(raw_md5, keys, sizeof(keys));

	int written = sprintf(out_frame,
		"HTTP/1.1 101 WebSocket Protocol Handshake\r\n"
		"Upgrade: WebSocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Origin: %s\r\n"
		"Sec-WebSocket-Location: ws://%s%s\r\n",
		hs->origin,
		hs->host,
		hs->resource);
	if (hs->protocol)
		written+= sprintf(out_frame+written,
			"Sec-WebSocket-Protocol: %s\r\n", hs->protocol);
	written+= sprintf(out_frame+written, "\r\n");
	
	assert(written <= *out_len && written+sizeof(keys) <= *out_len); // not enough out buffer length
	memcpy(out_frame+written, raw_md5, sizeof(keys));
	*out_len = written + sizeof(keys);

	return WS_OPENING_FRAME;
}

enum ws_frame_type ws_make_frame(const char *data, size_t data_len,
	char *out_frame, size_t *out_len)
{
	enum ws_frame_type frame_type;

	// TODO intruduce binary frame type

	out_frame[0] = '\x00';
	memcpy(&out_frame[1], data, data_len);
	out_frame[ data_len+1 ] = '\xFF';
	*out_len = data_len+2;
	frame_type = WS_TEXT_FRAME;

	return frame_type;
}

enum ws_frame_type ws_parse_input_frame(const char *input_frame, size_t input_len,
	char *out_data, size_t *out_len)
{
	enum ws_frame_type frame_type;

	assert(out_len);
	assert(input_len);

	if (input_len < 2)
		return WS_INCOMPLETE_FRAME;

	if (input_frame[0] == '\x00')
	{
		const char *data_start = &input_frame[1];
		char *end = memchr(data_start, '\xFF', input_len-1);
		if (end) {
			assert(end-data_start <= *out_len);
			memcpy(out_data, data_start, end-data_start);
			*out_len = end-data_start;
			frame_type = WS_TEXT_FRAME;
		} else {
			frame_type = WS_INCOMPLETE_FRAME;
		}
	}
	else if (input_frame[0] == '\xFF')
	{
		if (input_frame[1] == '\x00')
			frame_type = WS_CLOSING_FRAME;
		else {
			// TODO introduce parcing WS_BINARY_FRAME
			frame_type = WS_ERROR_FRAME;
		}
	}
	else
		frame_type = WS_ERROR_FRAME;


	return frame_type;
}

// <editor-fold defaultstate="collapsed" desc="md5">
#ifndef HAVE_MD5

typedef struct MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
} MD5_CTX;

#if __BYTE_ORDER == 1234
#define byteReverse(buf, len)	/* Nothing */
#else

/*
 * Note: this code is harmless on little-endian machines.
 */
static void
byteReverse(unsigned char *buf, unsigned longs)
{
	uint32_t t;
	do {
		t = (uint32_t) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
			((unsigned) buf[1] << 8 | buf[0]);
		*(uint32_t *) buf = t;
		buf += 4;
	} while (--longs);
}
#endif /* __BYTE_ORDER */

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
static void
MD5Init(MD5_CTX *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;

	ctx->bits[0] = 0;
	ctx->bits[1] = 0;
}

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void
MD5Transform(uint32_t buf[4], uint32_t const in[16])
{
	register uint32_t a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
	MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
	MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
	MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
	MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
	MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
	MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
	MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
	MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
	MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
	MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
	MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
	MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static void
MD5Update(MD5_CTX *ctx, unsigned char const *buf, unsigned len)
{
	uint32_t t;

	/* Update bitcount */

	t = ctx->bits[0];
	if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
		ctx->bits[1]++; /* Carry from low to high */
	ctx->bits[1] += len >> 29;

	t = (t >> 3) & 0x3f; /* Bytes already in shsInfo->data */

	/* Handle any leading odd-sized chunks */

	if (t) {
		unsigned char *p = (unsigned char *) ctx->in + t;

		t = 64 - t;
		if (len < t) {
			memcpy(p, buf, len);
			return;
		}
		memcpy(p, buf, t);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (uint32_t *) ctx->in);
		buf += t;
		len -= t;
	}
	/* Process data in 64-byte chunks */

	while (len >= 64) {
		memcpy(ctx->in, buf, 64);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (uint32_t *) ctx->in);
		buf += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */

	memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static void
MD5Final(unsigned char digest[16], MD5_CTX *ctx)
{
	unsigned count;
	unsigned char *p;

	/* Compute number of bytes mod 64 */
	count = (ctx->bits[0] >> 3) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	p = ctx->in + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		byteReverse(ctx->in, 16);
		MD5Transform(ctx->buf, (uint32_t *) ctx->in);

		/* Now fill the next block with 56 bytes */
		memset(ctx->in, 0, 56);
	} else {
		/* Pad block to 56 bytes */
		memset(p, 0, count - 8);
	}
	byteReverse(ctx->in, 14);

	/* Append length in bits and transform */
	((uint32_t *) ctx->in)[14] = ctx->bits[0];
	((uint32_t *) ctx->in)[15] = ctx->bits[1];

	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	byteReverse((unsigned char *) ctx->buf, 4);
	memcpy(digest, ctx->buf, 16);
	memset((char *) ctx, 0, sizeof (ctx)); /* In case it's sensitive */
}
#endif /* !HAVE_MD5 */

/*
 * Return stringified MD5 hash for list of vectors.
 * out_md5 must point to 16-bytes buffer
 */
static void
md5(char *out_md5, const unsigned char *in_buf, size_t in_len)
{
	const char *p;
	MD5_CTX ctx;

	MD5Init(&ctx);
	MD5Update(&ctx, (unsigned char *) in_buf, in_len);
	MD5Final(out_md5, &ctx);
}
// </editor-fold>
