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

#include "websocket.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 1
#endif

void nullhandshake(struct handshake *hs)
{
	hs->host = NULL;
	hs->key1 = NULL;
	hs->key2 = NULL;
	hs->origin = NULL;
	hs->protocol = NULL;
	hs->resource = NULL;
}

static uint32_t doStuffToObtainAnInt32(const uint8_t *key)
{
    uint8_t res_decimals[50] = "";
    uint8_t *tail_res = res_decimals;
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

static uint8_t* get_upto_linefeed(const uint8_t *start_from)
{
	uint8_t *write_to;
	uint8_t new_length = (uint8_t *)strstr(start_from, "\r\n") - start_from + 1;
	write_to = malloc(new_length); //+1 for '\x00'
	assert(write_to);
	memcpy(write_to, start_from, new_length-1);
	write_to[ new_length-1 ] = 0;

	return write_to;
}

enum ws_frame_type ws_parse_handshake(const uint8_t *input_frame, size_t input_len,
	struct handshake *hs)
{
	const uint8_t *input_ptr = input_frame;
	const uint8_t *end_ptr = input_frame + input_len;

	// measure resource size
	uint8_t *first = strchr(input_frame, ' ');
	if (!first)
		return WS_ERROR_FRAME;
	first++;
	uint8_t *second = strchr(first, ' ');
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
	uint8_t connection_flag = FALSE;
	uint8_t upgrade_flag = FALSE;
	while (input_ptr < end_ptr && input_ptr[0] != '\r' && input_ptr[1] != '\n') {
		if ( memcmp_P(input_ptr, host, strlen_P(host)) == 0 ) {
			input_ptr+= strlen(host);
			prepare(hs->host);
			hs->host = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp_P(input_ptr, origin, strlen_P(origin)) == 0 ) {
			input_ptr+= strlen(origin);
			prepare(hs->origin);
			hs->origin = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp_P(input_ptr, protocol, strlen_P(protocol)) == 0 ) {
			input_ptr+= strlen(protocol);
			prepare(hs->protocol);
			hs->protocol = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp_P(input_ptr, key1, strlen_P(key1)) == 0 ) {
			input_ptr+= strlen(key1);
			prepare(hs->key1);
			hs->key1 = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp_P(input_ptr, key2, strlen_P(key2)) == 0 ) {
			input_ptr+= strlen(key2);
			prepare(hs->key2);
			hs->key2 = get_upto_linefeed(input_ptr);
		} else
		if ( memcmp_P(input_ptr, connection, strlen_P(connection)) == 0 ) {
			connection_flag = TRUE;
		} else
		if ( memcmp_P(input_ptr, upgrade, strlen_P(upgrade)) == 0 ) {
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
	uint8_t *out_frame, size_t *out_len)
{
	assert(out_len && *out_len);
	assert(out_frame);
	// hs->key3 is always not NULL
	assert(hs && hs->origin && hs->host && hs->resource && hs->key1 && hs->key2);

    uint8_t chrkey1[4];
    uint8_t chrkey2[4];
    uint32_t key1 = doStuffToObtainAnInt32(hs->key1);
    uint32_t key2 = doStuffToObtainAnInt32(hs->key2);
    uint8_t i;
    for (i=0; i<4; i++)
        chrkey1[i] = key1<<(8*i)>>(8*3);
    for (i=0; i<4; i++)
        chrkey2[i] = key2<<(8*i)>>(8*3);

	uint8_t raw_md5[16];
    uint8_t keys[16];
    memcpy(keys, chrkey1, 4);
    memcpy(&keys[4], chrkey2, 4);
    memcpy(&keys[8], hs->key3, 8);
	md5(raw_md5, keys, sizeof(keys)*8);

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
	
	// if assert fail, that means, that we corrupt memory
	assert(written <= *out_len && written+sizeof(keys) <= *out_len);
	memcpy(out_frame+written, raw_md5, sizeof(keys));
	*out_len = written + sizeof(keys);

	return WS_OPENING_FRAME;
}

enum ws_frame_type ws_make_frame(const uint8_t *data, size_t data_len,
	uint8_t *out_frame, size_t *out_len, enum ws_frame_type frame_type)
{
	if (frame_type == WS_TEXT_FRAME) {
		// check on latin alphabet. If not - return error
		uint8_t *data_ptr = (uint8_t *)data;
		uint8_t *end_ptr = (uint8_t *)data+data_len;
		do {
			if (*data_ptr >> 7)
				return WS_ERROR_FRAME;
		} while ((++data_ptr < end_ptr));
		// TODO introduce binary frame type

		assert(*out_len >= data_len+2);
		out_frame[0] = '\x00';
		memcpy(&out_frame[1], data, data_len);
		out_frame[ data_len+1 ] = '\xFF';
		*out_len = data_len+2;
	} else {
		frame_type = WS_ERROR_FRAME;
	}

	return frame_type;
}

enum ws_frame_type ws_parse_input_frame(const uint8_t *input_frame, size_t input_len,
	uint8_t *out_data, size_t *out_len)
{
	enum ws_frame_type frame_type;

	assert(out_len);
	assert(input_len);

	if (input_len < 2)
		return WS_INCOMPLETE_FRAME;

	if (input_frame[0] == 0x00)
	{
		const uint8_t *data_start = &input_frame[1];
		uint8_t *end = (uint8_t *)memchr(data_start, 0xFF, input_len-1);
		if (end) {
			assert(end-data_start <= *out_len);
			memcpy(out_data, data_start, end-data_start);
			*out_len = end-data_start;
			frame_type = WS_TEXT_FRAME;
		} else {
			frame_type = WS_INCOMPLETE_FRAME;
		}
	}
	else if (input_frame[0] == 0xFF)
	{
		if (input_frame[1] == 0x00)
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
