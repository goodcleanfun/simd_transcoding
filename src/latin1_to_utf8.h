#ifndef LATIN1_TO_UTF8_H
#define LATIN1_TO_UTF8_H

#include <stdbool.h>
#include <stdint.h>

#include "simde_avx2/avx2.h"
#include "utf16_to_utf8_tables.h"
#include "result.h"

static inline utf_result_t convert_latin1_to_utf8_scalar(const char *latin1_input, size_t len,
                                                         char *utf8_output, size_t utf8_len) {
    const unsigned char *data = (const unsigned char *)latin1_input;
    size_t output_len = 0;
    size_t pos = 0;
    size_t skip_pos = 0;
    size_t utf8_pos = 0;

    while (pos < len && utf8_pos < utf8_len) {
        // try to convert the next block of 16 ASCII bytes
        if (pos >= skip_pos && pos + 16 <= len &&
            utf8_pos + 16 <= utf8_len) {
            uint64_t v1;
            memcpy(&v1, data + pos, sizeof(uint64_t));
            uint64_t v2;
            memcpy(&v2, data + pos + sizeof(uint64_t), sizeof(uint64_t));
            // We are only interested in these bits: 1000 1000 1000 1000
            // so it makes sense to concatenate everything
            uint64_t v = v1 | v2;
            if ((v & 0x8080808080808080) == 0) {
                // if *none of these are set, e.g. all of them are zero,
                // then everything is ASCII
                memcpy(utf8_output + utf8_pos, data + pos, 16);
                utf8_pos += 16;
                pos += 16;
            } else {
                // At least one of the next 16 bytes is not ASCII, we will process them
                // one by one
                skip_pos = pos + 16;
            }
        } else {
            const unsigned char byte = data[pos];
            if ((byte & 0x80) == 0) {
                // ASCII, will generate one UTF-8 byte
                utf8_output[utf8_pos++] = byte;
                pos++;
            } else if (utf8_pos + 2 <= utf8_len) {
                // will generate two UTF-8 bytes
                utf8_output[utf8_pos++] = (char)((byte >> 6) | 0b11000000);
                utf8_output[utf8_pos++] = (char)((byte & 0b111111) | 0b10000000);
                pos++;
            } else {
                return (utf_result_t){
                    .read_len = pos,
                    .written_len = utf8_pos,
                    .return_code = SIMDUTF_OUTPUT_BUFFER_TOO_SMALL
                };
            }
        }
    }

    return (utf_result_t){
        .read_len = pos,
        .written_len = utf8_pos,
        .return_code = SIMDUTF_SUCCESS
    };
}

utf_result_t convert_latin1_to_utf8(const char *latin1_input, size_t len,
                                    char *utf8_output, size_t utf8_len) {
    const char *end = latin1_input + len;
    const simde__m256i v_0000 = simde_mm256_setzero_si256();
    const simde__m256i v_c080 = simde_mm256_set1_epi16((int16_t)0xc080);
    const simde__m256i v_ff80 = simde_mm256_set1_epi16((int16_t)0xff80);
    const size_t safety_margin = 12;

    size_t read_len = 0;
    size_t output_len = 0;

    while (end - latin1_input >= (ptrdiff_t)(16 + safety_margin) && utf8_len >= (output_len + 16 + safety_margin)) {
      simde__m128i in8 = simde_mm_loadu_si128((simde__m128i *)latin1_input);
      // a single 16-bit UTF-16 word can yield 1, 2 or 3 UTF-8 bytes
      const simde__m128i v_80 = simde_mm_set1_epi8((char)0x80);
      if (simde_mm_testz_si128(in8, v_80)) { // ASCII fast path!!!!
          // 1. store (16 bytes)
          simde_mm_storeu_si128((simde__m128i *)utf8_output, in8);
          // 2. adjust pointers
          latin1_input += 16;
          utf8_output += 16;
          read_len += 16;
          output_len += 16;
          continue; // we are done for this round!
      }
      // We proceed only with the first 16 bytes.
      const simde__m256i in = simde_mm256_cvtepu8_epi16((in8));

      // 1. prepare 2-byte values
      // input 16-bit word : [0000|0000|aabb|bbbb] x 8
      // expected output   : [1100|00aa|10bb|bbbb] x 8
      const simde__m256i v_1f00 = simde_mm256_set1_epi16((int16_t)0x1f00);
      const simde__m256i v_003f = simde_mm256_set1_epi16((int16_t)0x003f);

      // t0 = [0000|00aa|bbbb|bb00]
      const simde__m256i t0 = simde_mm256_slli_epi16(in, 2);
      // t1 = [0000|00aa|0000|0000]
      const simde__m256i t1 = simde_mm256_and_si256(t0, v_1f00);
      // t2 = [0000|0000|00bb|bbbb]
      const simde__m256i t2 = simde_mm256_and_si256(in, v_003f);
      // t3 = [000a|aaaa|00bb|bbbb]
      const simde__m256i t3 = simde_mm256_or_si256(t1, t2);
      // t4 = [1100|00aa|10bb|bbbb]
      const simde__m256i t4 = simde_mm256_or_si256(t3, v_c080);

      // 2. merge ASCII and 2-byte codewords

      // no bits set above 7th bit
      const simde__m256i one_byte_bytemask = simde_mm256_cmpeq_epi16(simde_mm256_and_si256(in, v_ff80), v_0000);
      const uint32_t one_byte_bitmask = (uint32_t)(simde_mm256_movemask_epi8(one_byte_bytemask));

      const simde__m256i utf8_unpacked = simde_mm256_blendv_epi8(t4, in, one_byte_bytemask);

      // 3. prepare bitmask for 8-bit lookup
      const uint32_t M0 = one_byte_bitmask & 0x55555555;
      const uint32_t M1 = M0 >> 7;
      const uint32_t M2 = (M1 | M0) & 0x00ff00ff;
      // 4. pack the bytes

      const uint8_t *row =
          &utf16_to_utf8_tables_pack_1_2_utf8_bytes[(uint8_t)(M2)][0];
      const uint8_t *row_2 =
          &utf16_to_utf8_tables_pack_1_2_utf8_bytes[(uint8_t)(M2 >> 16)][0];

      const simde__m128i shuffle = simde_mm_loadu_si128((simde__m128i *)(row + 1));
      const simde__m128i shuffle_2 = simde_mm_loadu_si128((simde__m128i *)(row_2 + 1));

      const simde__m256i utf8_packed = simde_mm256_shuffle_epi8(
          utf8_unpacked, simde_mm256_setr_m128i(shuffle, shuffle_2));
      // 5. store bytes
      simde_mm_storeu_si128((simde__m128i *)utf8_output,
                       simde_mm256_castsi256_si128(utf8_packed));
      utf8_output += row[0];
      simde_mm_storeu_si128((simde__m128i *)utf8_output,
                       simde_mm256_extractf128_si256(utf8_packed, 1));
      utf8_output += row_2[0];
      // 6. adjust pointers
      latin1_input += 16;
      read_len += 16;
      output_len += row[0] + row_2[0];
      continue;

    } // while

    size_t remaining_len = end - latin1_input;
    size_t remaining_utf8_len = utf8_len - output_len;
    if (remaining_len > 0) {
        utf_result_t scalar_result = convert_latin1_to_utf8_scalar(latin1_input, remaining_len, utf8_output, remaining_utf8_len);
        return (utf_result_t){
            .read_len = read_len + scalar_result.read_len,
            .written_len = output_len + scalar_result.written_len,
            .return_code = scalar_result.return_code
        };
    }
    return (utf_result_t){
        .read_len = read_len,
        .written_len = output_len,
        .return_code = SIMDUTF_SUCCESS
    };
}

#endif