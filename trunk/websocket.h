/*
 * Copyright (c) 2010 Putilov Andrey
 *
 * Permission is hereby granted, free of uint8_tge, to any person obtaining a copy
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

#ifndef WEBSOCKET_H
#define	WEBSOCKET_H

#include <assert.h>
#include <stdint.h>
#include <stddef.h> /* size_t */

enum ws_frame_type {
	WS_ERROR_FRAME,
	WS_INCOMPLETE_FRAME,
	WS_TEXT_FRAME,
	WS_BINARY_FRAME,
	WS_OPENING_FRAME,
	WS_CLOSING_FRAME
};

struct handshake {
	char *resource;
	char *host;
	char *origin;
	char *protocol;
	char *key1;
	char *key2;
	char key3[8];
};

#ifdef	__cplusplus
extern "C" {
#endif

enum ws_frame_type ws_parse_handshake(const uint8_t *input_frame, size_t input_len,
	struct handshake *hs);

enum ws_frame_type ws_get_handshake_answer(const struct handshake *hs,
	uint8_t *out_frame, size_t *out_len);

enum ws_frame_type ws_make_frame(const uint8_t *data, size_t data_len,
	uint8_t *out_frame, size_t *out_len, enum ws_frame_type frame_type);

enum ws_frame_type ws_parse_input_frame(const uint8_t *input_frame, size_t input_len,
	uint8_t *out_data, size_t *out_len);

void nullhandshake(struct handshake *hs);

#ifdef	__cplusplus
}
#endif

#endif	/* WEBSOCKET_H */

