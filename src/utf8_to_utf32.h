
// Convert up to 12 bytes from utf8 to utf32 using a mask indicating the
// end of the code points. Only the least significant 12 bits of the mask
// are accessed.
// It returns how many bytes were consumed (up to 12).

#include <stdint.h>
#include <stdbool.h>

#include "simde_avx2/avx2.h"
#include "utf8_to_utf16_tables.h"


static inline utf_result_t convert_utf8_to_utf32_scalar(const char *buf, size_t len,
                                                        uint_least32_t *utf32_output, size_t output_len) {
    const uint8_t *data = (const uint8_t *)buf;
    size_t pos = 0;
    size_t output_pos = 0;
    uint_least32_t *start = utf32_output;

    while (pos < len && output_pos < output_len) {
        // try to convert the next block of 16 ASCII bytes
        // if it is safe to read 16 more bytes, check that they are ascii
        if (pos + 16 <= len) {
            if (output_pos + 16 > output_len) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_OUTPUT_BUFFER_TOO_SMALL
                };
            }
            uint64_t v1;
            memcpy(&v1, data + pos, sizeof(uint64_t));
            uint64_t v2;
            memcpy(&v2, data + pos + sizeof(uint64_t), sizeof(uint64_t));
            uint64_t v = v1 | v2;
            if ((v & 0x8080808080808080) == 0) {
                size_t final_pos = pos + 16;
                while (pos < final_pos) {
                    *utf32_output++ = (uint_least32_t)buf[pos];
                    output_pos++;
                    pos++;
                }
                continue;
            }
        }
        uint8_t leading_byte = data[pos]; // leading byte
        if (leading_byte < 0b10000000) {
            // converting one ASCII byte !!!
            *utf32_output++ = (uint_least32_t)leading_byte;
            pos++;
            output_pos++;
        } else if ((leading_byte & 0b11100000) == 0b11000000) {
            // We have a two-byte UTF-8
            if (pos + 1 >= len) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_SHORT
                };
            } // minimal bound checking
            if ((data[pos + 1] & 0b11000000) != 0b10000000) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_SHORT
                };
            }
            // range check
            uint32_t code_point =
                    (leading_byte & 0b00011111) << 6 | (data[pos + 1] & 0b00111111);
            if (code_point < 0x80 || 0x7ff < code_point) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_OVERLONG
                };
            }
            *utf32_output++ = (uint_least32_t)code_point;
            output_pos++;
            pos += 2;
        } else if ((leading_byte & 0b11110000) == 0b11100000) {
            // We have a three-byte UTF-8
            if (pos + 2 >= len) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_SHORT
                };
            } // minimal bound checking

            if ((data[pos + 1] & 0b11000000) != 0b10000000) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_SHORT
                };
            }
            if ((data[pos + 2] & 0b11000000) != 0b10000000) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_SHORT
                };
            }
            // range check
            uint32_t code_point = (leading_byte & 0b00001111) << 12 |
                                  (data[pos + 1] & 0b00111111) << 6 |
                                  (data[pos + 2] & 0b00111111);
            if (code_point < 0x800 || 0xffff < code_point) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_OVERLONG
                };
            }
            if (0xd7ff < code_point && code_point < 0xe000) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_SURROGATE
                };
            }
            *utf32_output++ = (uint_least32_t)code_point;
            output_pos++;
            pos += 3;
        } else if ((leading_byte & 0b11111000) == 0b11110000) { // 0b11110000
            // we have a 4-byte UTF-8 word.
            if (pos + 3 >= len) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_SHORT
                };
            } // minimal bound checking
            if ((data[pos + 1] & 0b11000000) != 0b10000000) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_SHORT
                };
            }
            if ((data[pos + 2] & 0b11000000) != 0b10000000) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_SHORT
                };
            }
            if ((data[pos + 3] & 0b11000000) != 0b10000000) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_SHORT
                };
            }

            // range check
            uint32_t code_point = (leading_byte & 0b00000111) << 18 |
                                  (data[pos + 1] & 0b00111111) << 12 |
                                  (data[pos + 2] & 0b00111111) << 6 |
                                  (data[pos + 3] & 0b00111111);
            if (code_point <= 0xffff) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_OVERLONG
                };
            }
            if (0x10ffff < code_point) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_LARGE
                };
            }
            *utf32_output++ = (uint_least32_t)code_point;
            output_pos++;
            pos += 4;
        } else {
            // we either have too many continuation bytes or an invalid leading byte
            if ((leading_byte & 0b11000000) == 0b10000000) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_LONG
                };
            } else {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_HEADER_BITS
                };
            }
        }
    }
    return (utf_result_t) {
        .read_len = pos,
        .written_len = output_pos,
        .return_code = SIMDUTF_SUCCESS
    };
}


static inline utf_result_t rewind_and_convert_utf8_to_utf32(size_t prior_bytes,
                                                            const char *buf, size_t len,
                                                            uint_least32_t *utf32_output, size_t output_len) {
    size_t extra_len = 0;
    // We potentially need to go back in time and find a leading byte.
    // 3 bytes in the past + current position
    size_t how_far_back = 3;
    if (how_far_back > prior_bytes) {
        how_far_back = prior_bytes;
    }
    bool found_leading_bytes = false;
    // important: it is i <= how_far_back and not 'i < how_far_back'.
    for (size_t i = 0; i <= how_far_back; i++) {
        unsigned char byte = buf[-(ptrdiff_t)i];
        found_leading_bytes = ((byte & 0b11000000) != 0b10000000);
        if (found_leading_bytes) {
            if (i > 0 && byte < 128) {
                // If we had to go back and the leading byte is ascii
                // then we can stop right away.
                return (utf_result_t) {
                    .read_len = 0 - i + 1,
                    .written_len = 0,
                    .return_code = SIMDUTF_TOO_LONG
                };
            }
            buf -= i;
            extra_len = i;
            break;
        }
    }
    //
    // It is possible for this function to return a negative count in its result.
    // size_t is described in the C Standard as <stddef.h>. C Standard Section 4.1.5
    // defines size_t as an unsigned integral type of the result of the sizeof operator
    //
    // An unsigned type will simply wrap round arithmetically (well defined).
    //
    if (!found_leading_bytes) {
        // If how_far_back == 3, we may have four consecutive continuation bytes!!!
        // [....] [continuation] [continuation] [continuation] | [buf is
        // continuation] Or we possibly have a stream that does not start with a
        // leading byte.
        return (utf_result_t) {
            .read_len = 0 - how_far_back,
            .written_len = 0,
            .return_code = SIMDUTF_TOO_LONG
        };
    }

    utf_result_t res = convert_utf8_to_utf32_scalar(buf, len + extra_len, utf32_output, output_len);
    if (res.return_code != SIMDUTF_SUCCESS) {
        res.read_len -= extra_len;
    }
    return res;
}



static inline simde__m256i check_special_cases(const simde__m256i input, const simde__m256i prev1) {
    // Bit 0 = Too Short (lead byte/ASCII followed by lead byte/ASCII)
    // Bit 1 = Too Long (ASCII followed by continuation)
    // Bit 2 = Overlong 3-byte
    // Bit 4 = Surrogate
    // Bit 5 = Overlong 2-byte
    // Bit 7 = Two Continuations
    const uint8_t TOO_SHORT = 1 << 0;  // 11______ 0_______
                                       // 11______ 11______
    const uint8_t TOO_LONG = 1 << 1;   // 0_______ 10______
    const uint8_t OVERLONG_3 = 1 << 2; // 11100000 100_____
    const uint8_t SURROGATE = 1 << 4;  // 11101101 101_____
    const uint8_t OVERLONG_2 = 1 << 5; // 1100000_ 10______
    const uint8_t TWO_CONTS = 1 << 7;  // 10______ 10______
    const uint8_t TOO_LARGE = 1 << 3;  // 11110100 1001____
                                       // 11110100 101_____
                                       // 11110101 1001____
                                       // 11110101 101_____
                                       // 1111011_ 1001____
                                       // 1111011_ 101_____
                                       // 11111___ 1001____
                                       // 11111___ 101_____
    const uint8_t TOO_LARGE_1000 = 1 << 6;
    // 11110101 1000____
    // 1111011_ 1000____
    // 11111___ 1000____
    const uint8_t OVERLONG_4 = 1 << 6; // 11110000 1000____

    const simde__m256i prev1_shr = simde_mm256_and_si256(
        simde_mm256_srli_epi16(prev1, 4),
        simde_mm256_set1_epi8((uint8_t)(0xFFu >> 4))
    );

    const uint8_t byte_1_high_lookups[16] = {
            // 0_______ ________ <ASCII in byte 1>
            TOO_LONG, TOO_LONG, TOO_LONG, TOO_LONG, TOO_LONG, TOO_LONG, TOO_LONG,
            TOO_LONG,
            // 10______ ________ <continuation in byte 1>
            TWO_CONTS, TWO_CONTS, TWO_CONTS, TWO_CONTS,
            // 1100____ ________ <two byte lead in byte 1>
            TOO_SHORT | OVERLONG_2,
            // 1101____ ________ <two byte lead in byte 1>
            TOO_SHORT,
            // 1110____ ________ <three byte lead in byte 1>
            TOO_SHORT | OVERLONG_3 | SURROGATE,
            // 1111____ ________ <four+ byte lead in byte 1>
            TOO_SHORT | TOO_LARGE | TOO_LARGE_1000 | OVERLONG_4
    };

    simde__m256i byte_1_high_lookup_table = simde_mm256_setr_epi8(
        byte_1_high_lookups[0], byte_1_high_lookups[1], byte_1_high_lookups[2], byte_1_high_lookups[3],
        byte_1_high_lookups[4], byte_1_high_lookups[5], byte_1_high_lookups[6], byte_1_high_lookups[7],
        byte_1_high_lookups[8], byte_1_high_lookups[9], byte_1_high_lookups[10], byte_1_high_lookups[11],
        byte_1_high_lookups[12], byte_1_high_lookups[13], byte_1_high_lookups[14], byte_1_high_lookups[15],
        byte_1_high_lookups[0], byte_1_high_lookups[1], byte_1_high_lookups[2], byte_1_high_lookups[3],
        byte_1_high_lookups[4], byte_1_high_lookups[5], byte_1_high_lookups[6], byte_1_high_lookups[7],
        byte_1_high_lookups[8], byte_1_high_lookups[9], byte_1_high_lookups[10], byte_1_high_lookups[11],
        byte_1_high_lookups[12], byte_1_high_lookups[13], byte_1_high_lookups[14], byte_1_high_lookups[15]
    );

    simde__m256i byte_1_high = simde_mm256_shuffle_epi8(byte_1_high_lookup_table, prev1_shr);

    // These all have ____ in byte 1 .
    const uint8_t CARRY = TOO_SHORT | TOO_LONG | TWO_CONTS;

    const uint8_t byte_1_low_lookups[16] = {
        // ____0000 ________
        CARRY | OVERLONG_3 | OVERLONG_2 | OVERLONG_4,
        // ____0001 ________
        CARRY | OVERLONG_2,
        // ____001_ ________
        CARRY,
        CARRY,

        // ____0100 ________
        CARRY | TOO_LARGE,
        // ____0101 ________
        CARRY | TOO_LARGE | TOO_LARGE_1000,
        // ____011_ ________
        CARRY | TOO_LARGE | TOO_LARGE_1000,
        CARRY | TOO_LARGE | TOO_LARGE_1000,

        // ____1___ ________
        CARRY | TOO_LARGE | TOO_LARGE_1000,
        CARRY | TOO_LARGE | TOO_LARGE_1000,
        CARRY | TOO_LARGE | TOO_LARGE_1000,
        CARRY | TOO_LARGE | TOO_LARGE_1000,
        CARRY | TOO_LARGE | TOO_LARGE_1000,
        // ____1101 ________
        CARRY | TOO_LARGE | TOO_LARGE_1000 | SURROGATE,
        CARRY | TOO_LARGE | TOO_LARGE_1000,
        CARRY | TOO_LARGE | TOO_LARGE_1000
    };

    const simde__m256i byte_1_low_lookup_table = simde_mm256_setr_epi8(
        byte_1_low_lookups[0], byte_1_low_lookups[1], byte_1_low_lookups[2], byte_1_low_lookups[3],
        byte_1_low_lookups[4], byte_1_low_lookups[5], byte_1_low_lookups[6], byte_1_low_lookups[7],
        byte_1_low_lookups[8], byte_1_low_lookups[9], byte_1_low_lookups[10], byte_1_low_lookups[11],
        byte_1_low_lookups[12], byte_1_low_lookups[13], byte_1_low_lookups[14], byte_1_low_lookups[15],
        byte_1_low_lookups[0], byte_1_low_lookups[1], byte_1_low_lookups[2], byte_1_low_lookups[3],
        byte_1_low_lookups[4], byte_1_low_lookups[5], byte_1_low_lookups[6], byte_1_low_lookups[7],
        byte_1_low_lookups[8], byte_1_low_lookups[9], byte_1_low_lookups[10], byte_1_low_lookups[11],
        byte_1_low_lookups[12], byte_1_low_lookups[13], byte_1_low_lookups[14], byte_1_low_lookups[15]
    );

    simde__m256i byte_1_low = simde_mm256_shuffle_epi8(
        byte_1_low_lookup_table, 
        simde_mm256_and_si256(
            prev1,
            simde_mm256_set1_epi8(0x0F)
        )
    );

    const simde__m256i input_shr = simde_mm256_and_si256(
        simde_mm256_srli_epi16(input, 4),
        simde_mm256_set1_epi8((uint8_t)(0xFFu >> 4))
    );

    const uint8_t byte_2_high_lookups[16] = {
        // ________ 0_______ <ASCII in byte 2>
        TOO_SHORT, TOO_SHORT, TOO_SHORT, TOO_SHORT, TOO_SHORT, TOO_SHORT,
        TOO_SHORT, TOO_SHORT,

        // ________ 1000____
        TOO_LONG | OVERLONG_2 | TWO_CONTS | OVERLONG_3 | TOO_LARGE_1000 |
                OVERLONG_4,
        // ________ 1001____
        TOO_LONG | OVERLONG_2 | TWO_CONTS | OVERLONG_3 | TOO_LARGE,
        // ________ 101_____
        TOO_LONG | OVERLONG_2 | TWO_CONTS | SURROGATE | TOO_LARGE,
        TOO_LONG | OVERLONG_2 | TWO_CONTS | SURROGATE | TOO_LARGE,

        // ________ 11______
        TOO_SHORT, TOO_SHORT, TOO_SHORT, TOO_SHORT
    };

    simde__m256i byte_2_high_lookup_table = simde_mm256_setr_epi8(
        byte_2_high_lookups[0], byte_2_high_lookups[1], byte_2_high_lookups[2], byte_2_high_lookups[3],
        byte_2_high_lookups[4], byte_2_high_lookups[5], byte_2_high_lookups[6], byte_2_high_lookups[7],
        byte_2_high_lookups[8], byte_2_high_lookups[9], byte_2_high_lookups[10], byte_2_high_lookups[11],
        byte_2_high_lookups[12], byte_2_high_lookups[13], byte_2_high_lookups[14], byte_2_high_lookups[15],
        byte_2_high_lookups[0], byte_2_high_lookups[1], byte_2_high_lookups[2], byte_2_high_lookups[3],
        byte_2_high_lookups[4], byte_2_high_lookups[5], byte_2_high_lookups[6], byte_2_high_lookups[7],
        byte_2_high_lookups[8], byte_2_high_lookups[9], byte_2_high_lookups[10], byte_2_high_lookups[11],
        byte_2_high_lookups[12], byte_2_high_lookups[13], byte_2_high_lookups[14], byte_2_high_lookups[15]
    );

    simde__m256i byte_2_high = simde_mm256_shuffle_epi8(byte_2_high_lookup_table, input_shr);

    return simde_mm256_and_si256(
        simde_mm256_and_si256(byte_1_high, byte_1_low),
        byte_2_high
    );
}


static inline simde__m256i check_multibyte_lengths(const simde__m256i input, const simde__m256i prev_input, const simde__m256i sc) {
    simde__m256i prev2 = simde_mm256_alignr_epi8(
        input, simde_mm256_permute2x128_si256(prev_input, input, 0x21), 16 - 2);
    simde__m256i prev3 = simde_mm256_alignr_epi8(
        input, simde_mm256_permute2x128_si256(prev_input, input, 0x21), 16 - 3);

    simde__m256i is_third_byte = simde_mm256_subs_epu8(prev2, simde_mm256_set1_epi8(0xe0u - 0x80));
    simde__m256i is_fourth_byte = simde_mm256_subs_epu8(prev3, simde_mm256_set1_epi8(0xf0u - 0x80));

    simde__m256i must23 = simde_mm256_or_si256(is_third_byte, is_fourth_byte);

    simde__m256i must23_80 = simde_mm256_and_si256(must23, simde_mm256_set1_epi8(0x80));

    return simde_mm256_xor_si256(must23_80, sc);
}

static inline utf_result_t convert_masked_utf8_to_utf32(const char *input, size_t len,
                                                        const uint64_t utf8_end_of_code_point_mask,
                                                        uint_least32_t *utf32_output, size_t output_len) {
    // we use an approach where we try to process up to 12 input bytes.
    // Why 12 input bytes and not 16? Because we are concerned with the size of
    // the lookup tables. Also 12 is nicely divisible by two and three.
    //
    //
    // Optimization note: our main path below is load-latency dependent. Thus it
    // is maybe beneficial to have fast paths that depend on branch prediction but
    // have less latency. This results in more instructions but, potentially, also
    // higher speeds.
    //
    // We first try a few fast paths.
    const simde__m128i in = simde_mm_loadu_si128((simde__m128i *)input);
    const uint16_t input_utf8_end_of_code_point_mask =
            utf8_end_of_code_point_mask & 0xfff;
    if (utf8_end_of_code_point_mask == 0xfff) {
        // We process the data in chunks of 12 bytes.
        simde_mm256_storeu_si256((simde__m256i *)(utf32_output),
                                                simde_mm256_cvtepu8_epi32(in));
        simde_mm256_storeu_si256((simde__m256i *)(utf32_output + 8),
                                                         simde_mm256_cvtepu8_epi32(simde_mm_srli_si128(in, 8)));
        // We consumed 12 bytes and wrote 12 code points.
        return (utf_result_t) {
            .read_len = 12,
            .written_len = 12,
            .return_code = SIMDUTF_SUCCESS
        };
    }
    if (((utf8_end_of_code_point_mask & 0xffff) == 0xaaaa)) {
        // We want to take 8 2-byte UTF-8 code units and turn them into 8 4-byte
        // UTF-32 code units. There is probably a more efficient sequence, but the
        // following might do.
        const simde__m128i sh =
                simde_mm_setr_epi8(1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14);
        const simde__m128i perm = simde_mm_shuffle_epi8(in, sh);
        const simde__m128i ascii = simde_mm_and_si128(perm, simde_mm_set1_epi16(0x7f));
        const simde__m128i highbyte = simde_mm_and_si128(perm, simde_mm_set1_epi16(0x1f00));
        const simde__m128i composed = simde_mm_or_si128(ascii, simde_mm_srli_epi16(highbyte, 2));
        simde_mm256_storeu_si256((simde__m256i *)utf32_output,
                                                simde_mm256_cvtepu16_epi32(composed));
        // We consumed 16 bytes and wrote 8 code points.
        return (utf_result_t) {
            .read_len = 16,
            .written_len = 8,
            .return_code = SIMDUTF_SUCCESS
        };
    }
    if (input_utf8_end_of_code_point_mask == 0x924) {
        // We want to take 4 3-byte UTF-8 code units and turn them into 4 4-byte
        // UTF-32 code units. There is probably a more efficient sequence, but the
        // following might do.
        const simde__m128i sh =
                simde_mm_setr_epi8(2, 1, 0, -1, 5, 4, 3, -1, 8, 7, 6, -1, 11, 10, 9, -1);
        const simde__m128i perm = simde_mm_shuffle_epi8(in, sh);
        const simde__m128i ascii =
                simde_mm_and_si128(perm, simde_mm_set1_epi32(0x7f)); // 7 or 6 bits
        const simde__m128i middlebyte =
                simde_mm_and_si128(perm, simde_mm_set1_epi32(0x3f00)); // 5 or 6 bits
        const simde__m128i middlebyte_shifted = simde_mm_srli_epi32(middlebyte, 2);
        const simde__m128i highbyte =
                simde_mm_and_si128(perm, simde_mm_set1_epi32(0x0f0000)); // 4 bits
        const simde__m128i highbyte_shifted = simde_mm_srli_epi32(highbyte, 4);
        const simde__m128i composed =
                simde_mm_or_si128(simde_mm_or_si128(ascii, middlebyte_shifted), highbyte_shifted);
        simde_mm_storeu_si128((simde__m128i *)utf32_output, composed);
        return (utf_result_t) {
            .read_len = 12,
            .written_len = 4,
            .return_code = SIMDUTF_SUCCESS
        };
    }
    /// We do not have a fast path available, so we fallback.

    const uint8_t idx =
            utf8_to_utf16_tables_utf8bigindex[input_utf8_end_of_code_point_mask][0];
    const uint8_t consumed =
            utf8_to_utf16_tables_utf8bigindex[input_utf8_end_of_code_point_mask][1];

    size_t codepoints_written = 0;

    if (idx < 64) {
        // SIX (6) input code-code units
        // this is a relatively easy scenario
        // we process SIX (6) input code-code units. The max length in bytes of six
        // code code units spanning between 1 and 2 bytes each is 12 bytes. On
        // processors where pdep/pext is fast, we might be able to use a small
        // lookup table.
        const simde__m128i sh =
                simde_mm_loadu_si128((const simde__m128i *)utf8_to_utf16_tables_shufutf8[idx]);
        const simde__m128i perm = simde_mm_shuffle_epi8(in, sh);
        const simde__m128i ascii = simde_mm_and_si128(perm, simde_mm_set1_epi16(0x7f));
        const simde__m128i highbyte = simde_mm_and_si128(perm, simde_mm_set1_epi16(0x1f00));
        const simde__m128i composed = simde_mm_or_si128(ascii, simde_mm_srli_epi16(highbyte, 2));
        simde_mm256_storeu_si256((simde__m256i *)utf32_output,
                                                simde_mm256_cvtepu16_epi32(composed));
        codepoints_written = 6; // We wrote 24 bytes, 6 code points. There is a potential
        // overflow of 32 - 24 = 8 bytes.
    } else if (idx < 145) {
        // FOUR (4) input code-code units
        const simde__m128i sh =
                simde_mm_loadu_si128((const simde__m128i *)utf8_to_utf16_tables_shufutf8[idx]);
        const simde__m128i perm = simde_mm_shuffle_epi8(in, sh);
        const simde__m128i ascii =
                simde_mm_and_si128(perm, simde_mm_set1_epi32(0x7f)); // 7 or 6 bits
        const simde__m128i middlebyte =
                simde_mm_and_si128(perm, simde_mm_set1_epi32(0x3f00)); // 5 or 6 bits
        const simde__m128i middlebyte_shifted = simde_mm_srli_epi32(middlebyte, 2);
        const simde__m128i highbyte =
                simde_mm_and_si128(perm, simde_mm_set1_epi32(0x0f0000)); // 4 bits
        const simde__m128i highbyte_shifted = simde_mm_srli_epi32(highbyte, 4);
        const simde__m128i composed =
                simde_mm_or_si128(simde_mm_or_si128(ascii, middlebyte_shifted), highbyte_shifted);
        simde_mm_storeu_si128((simde__m128i *)utf32_output, composed);
        codepoints_written = 4;
    } else if (idx < 209) {
        // TWO (2) input code-code units
        const simde__m128i sh =
                simde_mm_loadu_si128((const simde__m128i *)utf8_to_utf16_tables_shufutf8[idx]);
        const simde__m128i perm = simde_mm_shuffle_epi8(in, sh);
        const simde__m128i ascii = simde_mm_and_si128(perm, simde_mm_set1_epi32(0x7f));
        const simde__m128i middlebyte = simde_mm_and_si128(perm, simde_mm_set1_epi32(0x3f00));
        const simde__m128i middlebyte_shifted = simde_mm_srli_epi32(middlebyte, 2);
        simde__m128i middlehighbyte = simde_mm_and_si128(perm, simde_mm_set1_epi32(0x3f0000));
        // correct for spurious high bit
        const simde__m128i correct =
                simde_mm_srli_epi32(simde_mm_and_si128(perm, simde_mm_set1_epi32(0x400000)), 1);
        middlehighbyte = simde_mm_xor_si128(correct, middlehighbyte);
        const simde__m128i middlehighbyte_shifted = simde_mm_srli_epi32(middlehighbyte, 4);
        const simde__m128i highbyte = simde_mm_and_si128(perm, simde_mm_set1_epi32(0x07000000));
        const simde__m128i highbyte_shifted = simde_mm_srli_epi32(highbyte, 6);
        const simde__m128i composed =
                simde_mm_or_si128(simde_mm_or_si128(ascii, middlebyte_shifted),
                                         simde_mm_or_si128(highbyte_shifted, middlehighbyte_shifted));
        simde_mm_storeu_si128((simde__m128i *)utf32_output, composed);
        codepoints_written = 3; // We wrote 3 * 4 bytes, there is a potential overflow of 4 bytes.
    }
    return (utf_result_t) {
        .read_len = (size_t)consumed,
        .written_len = codepoints_written,
        .return_code = SIMDUTF_SUCCESS
    };
}


static inline simde__m256i check_utf8_bytes(simde__m256i input,
                                            simde__m256i prev_input) {
    // Flip prev1...prev3 so we can easily determine if they are 2+, 3+ or 4+
    // lead bytes (2, 3, 4-byte leads become large positive numbers instead of
    // small negative numbers)
    simde__m256i prev1 = simde_mm256_alignr_epi8(
        input, simde_mm256_permute2x128_si256(prev_input, input, 0x21), 16 - 1);

    simde__m256i sc = check_special_cases(input, prev1);
    return check_multibyte_lengths(input, prev_input, sc);
}


static inline void store_ascii_as_utf32(simde__m256i value, uint_least32_t *ptr) {
    simde_mm256_storeu_si256((simde__m256i *)ptr,
                        simde_mm256_cvtepu8_epi32(simde_mm256_castsi256_si128(value)));
    simde_mm256_storeu_si256((simde__m256i *)(ptr + 8),
                        simde_mm256_cvtepu8_epi32(simde_mm256_castsi256_si128(
                            simde_mm256_srli_si256(value, 8))));
    simde_mm256_storeu_si256(
        (simde__m256i *)(ptr + 16),
        simde_mm256_cvtepu8_epi32(simde_mm256_extractf128_si256(value, 1)));
    simde_mm256_storeu_si256((simde__m256i *)(ptr + 24),
                        simde_mm256_cvtepu8_epi32(simde_mm_srli_si128(
                            simde_mm256_extractf128_si256(value, 1), 8)));
}



static inline utf_result_t convert_utf8_to_utf32(const char *in, size_t len,
                                                 uint_least32_t *utf32_output, size_t output_len) {
    size_t output_pos = 0;
    size_t pos = 0;

    simde__m256i error = simde_mm256_set1_epi8(0);
    uint_least32_t *start = utf32_output;
    // In the worst case, we have the haswell kernel which can cause an overflow
    // of 8 bytes when calling convert_masked_utf8_to_utf32. If you skip the
    // last 16 bytes, and if the data is valid, then it is entirely safe because
    // 16 UTF-8 bytes generate much more than 8 bytes. However, you cannot
    // generally assume that you have valid UTF-8 input, so we are going to go
    // back from the end counting 8 leading bytes, to give us a good margin.
    size_t leading_byte = 0;
    size_t margin = len;
    for (; margin > 0 && leading_byte < 8; margin--) {
        leading_byte += ((int8_t)(in[margin - 1]) > -65);
    }
    // If the input is long enough, then we have that margin-1 is the fourth
    // last leading byte.
    const size_t safety_margin = len - margin + 1; // to avoid overruns!
    while (pos + 64 + safety_margin <= len) {
        simde__m256i chunk1 = simde_mm256_loadu_si256((const simde__m256i *)(in + pos));
        simde__m256i chunk2 = simde_mm256_loadu_si256((const simde__m256i *)(in + pos + 32));

        bool is_ascii = simde_mm256_movemask_epi8(
                            simde_mm256_or_si256(chunk1, chunk2)) == 0;

        if (is_ascii) {
            if (output_pos + 64 > output_len) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_OUTPUT_BUFFER_TOO_SMALL
                };
            }
            store_ascii_as_utf32(chunk1, utf32_output);
            utf32_output += 32;
            store_ascii_as_utf32(chunk2, utf32_output);
            utf32_output += 32;

            output_pos += 64;
            pos += 64;
        } else {
            // you might think that a for-loop would work, but under Visual Studio,
            // it is not good enough.
            simde__m256i zero = simde_mm256_set1_epi8(0);
            simde__m256i chunk1_check = check_utf8_bytes(chunk1, zero);
            error = simde_mm256_or_si256(error, chunk1_check);

            simde__m256i chunk2_check = check_utf8_bytes(chunk2, chunk1);
            error = simde_mm256_or_si256(error, chunk2_check);

            bool have_errors = !simde_mm256_testz_si256(error, error);
            if (have_errors) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_OUTPUT_BUFFER_TOO_SMALL
                };
            }

            simde__m256i mask = simde_mm256_set1_epi8(-65 + 1);
            simde__m256i chunk1_lt = simde_mm256_cmpgt_epi8(mask, chunk1);
            simde__m256i chunk2_lt = simde_mm256_cmpgt_epi8(mask, chunk2);

            uint64_t r_lo = (uint32_t)simde_mm256_movemask_epi8(chunk1_lt);
            uint64_t r_hi = (uint32_t)simde_mm256_movemask_epi8(chunk2_lt);
            uint64_t utf8_continuation_mask = r_lo | (r_hi << 32);

            if (utf8_continuation_mask & 1) {
                utf_result_t res = rewind_and_convert_utf8_to_utf32(
                        pos, in + pos, len - pos, utf32_output, output_len - output_pos);
                return (utf_result_t) {
                    .read_len = pos + res.read_len,
                    .written_len = output_pos + res.written_len,
                    .return_code = res.return_code
                };
            }
            uint64_t utf8_leading_mask = ~utf8_continuation_mask;
            uint64_t utf8_end_of_code_point_mask = utf8_leading_mask >> 1;
            // We process in blocks of up to 12 bytes except possibly
            // for fast paths which may process up to 16 bytes. For the
            // slow path to work, we should have at least 12 input bytes left.
            size_t max_starting_point = (pos + 64) - 12;
            // Next loop is going to run at least five times.
            while (pos < max_starting_point) {
                // Performance note: our ability to compute 'consumed' and
                // then shift and recompute is critical. If there is a
                // latency of, say, 4 cycles on getting 'consumed', then
                // the inner loop might have a total latency of about 6 cycles.
                // Yet we process between 6 to 12 inputs bytes, thus we get
                // a speed limit between 1 cycle/byte and 0.5 cycle/byte
                // for this section of the code. Hence, there is a limit
                // to how much we can further increase this latency before
                // it seriously harms performance.
                utf_result_t consumed = convert_masked_utf8_to_utf32(
                        in + pos, len - pos, utf8_end_of_code_point_mask, utf32_output, output_len - output_pos);
                pos += consumed.read_len;
                utf32_output += consumed.written_len;
                output_pos += consumed.written_len;
                utf8_end_of_code_point_mask >>= consumed.read_len;
            }
            // At this point there may remain between 0 and 12 bytes in the
            // 64-byte block. These bytes will be processed again. So we have an
            // 80% efficiency (in the worst case). In practice we expect an
            // 85% to 90% efficiency.
        }
    }

    if (!simde_mm256_testz_si256(error, error)) {
        utf_result_t res = rewind_and_convert_utf8_to_utf32(
                pos, in + pos, len - pos, utf32_output, output_len - output_pos);
        return (utf_result_t) {
            .read_len = pos + res.read_len,
            .written_len = output_pos + res.written_len,
            .return_code = res.return_code
        };
    }
    if (pos < len) {
        utf_result_t res = rewind_and_convert_utf8_to_utf32(
                pos, in + pos, len - pos, utf32_output, output_len - output_pos);
        if (res.return_code != SIMDUTF_SUCCESS) { // In case of error, we want the error position
            return (utf_result_t) {
                .read_len = pos + res.read_len,
                .written_len = output_pos + res.written_len,
                .return_code = res.return_code
            };
        } else {
            // In case of success, we want the number of word written
            pos += res.read_len;
            output_pos += res.written_len;
        }
    }
    return (utf_result_t) {
        .read_len = pos,
        .written_len = output_pos,
        .return_code = SIMDUTF_SUCCESS
    };
}


static inline utf_result_t convert_valid_utf8_to_utf32_scalar(const char *input, size_t len,
                                                              uint_least32_t *utf32_output, size_t output_len) {
    const uint8_t *data = (const uint8_t *)input;
    size_t pos = 0;
    size_t output_pos = 0;
    uint_least32_t *start = utf32_output;
    while (pos < len && output_pos < output_len) {
        // try to convert the next block of 8 ASCII bytes
        if (pos + 8 <= len) { // if it is safe to read 8 more bytes, check that they are ascii
            if (output_pos + 8 > output_len) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_OUTPUT_BUFFER_TOO_SMALL
                };
            }
            uint64_t v;
            memcpy(&v, data + pos, sizeof(uint64_t));
            if ((v & 0x8080808080808080) == 0) {
                size_t final_pos = pos + 8;
                while (pos < final_pos) {
                    *utf32_output++ = (uint_least32_t)data[pos];
                    pos++;
                    output_pos++;
                }
                continue;
            }
        }
        uint8_t leading_byte = data[pos]; // leading byte
        if (leading_byte < 0b10000000) {
            // converting one ASCII byte !!!
            *utf32_output++ = (uint_least32_t)leading_byte;
            output_pos++;
            pos++;
        } else if ((leading_byte & 0b11100000) == 0b11000000) {
            // We have a two-byte UTF-8
            if (pos + 1 >= len) {
                break;
            } // minimal bound checking
            *utf32_output++ = (uint_least32_t)(((leading_byte & 0b00011111) << 6) |
                                               (data[pos + 1] & 0b00111111));
            pos += 2;
            output_pos++;
        } else if ((leading_byte & 0b11110000) == 0b11100000) {
            // We have a three-byte UTF-8
            if (pos + 2 >= len) {
                break;
            } // minimal bound checking
            *utf32_output++ = (uint_least32_t)(((leading_byte & 0b00001111) << 12) |
                                               ((data[pos + 1] & 0b00111111) << 6) |
                                               (data[pos + 2] & 0b00111111));
            pos += 3;
            output_pos++;
        } else if ((leading_byte & 0b11111000) == 0b11110000) { // 0b11110000
            // we have a 4-byte UTF-8 word.
            if (pos + 3 >= len) {
                break;
            } // minimal bound checking
            uint32_t code_word = ((leading_byte & 0b00000111) << 18) |
                                  ((data[pos + 1] & 0b00111111) << 12) |
                                  ((data[pos + 2] & 0b00111111) << 6) |
                                  (data[pos + 3] & 0b00111111);
            *utf32_output++ = (uint_least32_t)(code_word);
            pos += 4;
            output_pos++;
        } else {
            // we may have a continuation
            if ((leading_byte & 0b11000000) == 0b10000000) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_TOO_LONG
                };
            } else {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_HEADER_BITS
                };
            }
        }
    }

    if (pos < len && output_pos == output_len) {
        return (utf_result_t) {
            .read_len = pos,
            .written_len = output_pos,
            .return_code = SIMDUTF_OUTPUT_BUFFER_TOO_SMALL
        };
    }

    return (utf_result_t) {
        .read_len = pos,
        .written_len = output_pos,
        .return_code = SIMDUTF_SUCCESS
    };
}


utf_result_t convert_valid_utf8_to_utf32(const char *input, size_t len,
                                         uint_least32_t *utf32_output, size_t output_len) {
    size_t pos = 0;
    size_t output_pos = 0;
    uint_least32_t *start = utf32_output;
    const size_t safety_margin = 16; // to avoid overruns!
    while (pos + 64 + safety_margin <= len) {
        simde__m256i chunk1 = simde_mm256_loadu_si256((const simde__m256i *)(input + pos));
        simde__m256i chunk2 = simde_mm256_loadu_si256((const simde__m256i *)(input + pos + 32));

        bool is_ascii = simde_mm256_movemask_epi8(
                            simde_mm256_or_si256(chunk1, chunk2)) == 0;

        if (is_ascii) {
            if (output_pos + 64 > output_len) {
                return (utf_result_t) {
                    .read_len = pos,
                    .written_len = output_pos,
                    .return_code = SIMDUTF_OUTPUT_BUFFER_TOO_SMALL
                };
            }
            store_ascii_as_utf32(chunk1, utf32_output);
            utf32_output += 32;
            store_ascii_as_utf32(chunk2, utf32_output);
            utf32_output += 32;

            output_pos += 64;
            pos += 64;
        } else {
            // -65 is 0b10111111 in two-complement's, so largest possible continuation
            // byte
            simde__m256i mask = simde_mm256_set1_epi8(-65 + 1);
            simde__m256i chunk1_lt = simde_mm256_cmpgt_epi8(mask, chunk1);
            simde__m256i chunk2_lt = simde_mm256_cmpgt_epi8(mask, chunk2);

            uint64_t r_lo = (uint32_t)simde_mm256_movemask_epi8(chunk1_lt);
            uint64_t r_hi = (uint32_t)simde_mm256_movemask_epi8(chunk2_lt);
            uint64_t utf8_continuation_mask = r_lo | (r_hi << 32);

            uint64_t utf8_leading_mask = ~utf8_continuation_mask;
            uint64_t utf8_end_of_code_point_mask = utf8_leading_mask >> 1;
            size_t max_starting_point = (pos + 64) - 12;
            while (pos < max_starting_point) {
                utf_result_t consumed = convert_masked_utf8_to_utf32(
                        input + pos, len - pos, utf8_end_of_code_point_mask, utf32_output, output_len - output_pos);
                pos += consumed.read_len;
                utf32_output += consumed.written_len;
                output_pos += consumed.written_len;
                utf8_end_of_code_point_mask >>= consumed.read_len;
            }
        }
    }

    utf_result_t res = convert_valid_utf8_to_utf32_scalar(input + pos, len - pos, utf32_output, output_len - output_pos);

    return (utf_result_t) {
        .read_len = pos + res.read_len,
        .written_len = output_pos + res.written_len,
        .return_code = res.return_code
    };
}