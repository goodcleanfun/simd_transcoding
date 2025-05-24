#ifndef UTF_RESULT_H
#define UTF_RESULT_H

#include <stdint.h>

typedef enum {
  SIMDUTF_SUCCESS = 0,
  SIMDUTF_HEADER_BITS,  // Any byte must have fewer than 5 header bits.
  SIMDUTF_TOO_SHORT,    // The leading byte must be followed by N-1 continuation bytes,
                        // where N is the UTF-8 character length This is also the error
                        // when the input is truncated.
  SIMDUTF_TOO_LONG,     // We either have too many consecutive continuation bytes or the
                        // string starts with a continuation byte.
  SIMDUTF_OVERLONG,     // The decoded character must be above U+7F for two-byte characters,
                        // U+7FF for three-byte characters, and U+FFFF for four-byte
                        // characters.
  SIMDUTF_TOO_LARGE,    // The decoded character must be less than or equal to
                        // U+10FFFF,less than or equal than U+7F for ASCII OR less than
                        // equal than U+FF for Latin1
  SIMDUTF_SURROGATE,    // The decoded character must be not be in U+D800...DFFF (UTF-8 or
                        // UTF-32) OR a high surrogate must be followed by a low surrogate
                        // and a low surrogate must be preceded by a high surrogate
                        // (UTF-16) OR there must be no surrogate at all (Latin1)
  SIMDUTF_INVALID_BASE64_CHARACTER, // Found a character that cannot be part of a valid
                                    // base64 string. This may include a misplaced
                                    // padding character ('=').
  SIMDUTF_BASE64_INPUT_REMAINDER,   // The base64 input terminates with a single
                                    // character, excluding padding (=). It is also used
                                    // in strict mode when padding is not adequate.
  SIMDUTF_BASE64_EXTRA_BITS,        // The base64 input terminates with non-zero
                                    // padding bits.
  SIMDUTF_OUTPUT_BUFFER_TOO_SMALL,  // The provided buffer is too small.
  SIMDUTF_OTHER                     // Not related to validation/transcoding.
} utf_return_code_t;

typedef struct {
    size_t read_len;
    size_t written_len;
    utf_return_code_t return_code;
} utf_result_t;

#endif