#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "greatest/greatest.h"
#include "aligned/aligned.h"
#include "latin1_to_utf8.h"
#include "utf8_to_utf32.h"

TEST test_latin1_to_utf8(void) {
    const char *data_str = (char *)"Tony! Toni! Ton\xe9!";
    size_t len = strlen((const char *)data_str);
    char *data = aligned_malloc(len, 32);
    memcpy(data, data_str, len);
    size_t utf8_output_len = len + 1;
    char *utf8_output = aligned_malloc(utf8_output_len, 32);

    utf_result_t converted = convert_latin1_to_utf8(data, len, utf8_output, utf8_output_len);
    ASSERT_EQ(converted.return_code, SIMDUTF_SUCCESS);
    ASSERT_EQ(converted.read_len, len);
    ASSERT_EQ(converted.written_len, utf8_output_len);
    ASSERT(strncmp(utf8_output, "Tony! Toni! Toné!", utf8_output_len) == 0);

    const char *data_str_long = (char *)"Tony! Toni! Ton\xe9! Tony! Toni! Ton\xe9! Tony! Toni! Ton\xe9! Tony! Toni! Ton\xe9!";
    size_t len_long = strlen(data_str_long);
    char *data_long = aligned_malloc(len_long, 32);
    memcpy(data_long, data_str_long, len_long);

    size_t utf8_output_len_long = len_long + 4;
    char *utf8_output_long = aligned_malloc(utf8_output_len_long, 32);

    utf_result_t converted_long = convert_latin1_to_utf8(data_long, len_long, utf8_output_long, utf8_output_len_long);
    ASSERT_EQ(converted_long.return_code, SIMDUTF_SUCCESS);
    ASSERT_EQ(converted_long.read_len, len_long);
    ASSERT_EQ(converted_long.written_len, utf8_output_len_long);
    ASSERT(strncmp(utf8_output_long, "Tony! Toni! Toné! Tony! Toni! Toné! Tony! Toni! Toné! Tony! Toni! Toné!", utf8_output_len_long) == 0);

    utf_result_t converted_too_short = convert_latin1_to_utf8(data_long, len_long, utf8_output, utf8_output_len);
    ASSERT_EQ(converted_too_short.return_code, SIMDUTF_SUCCESS);
    ASSERT_EQ(converted_too_short.read_len, len);
    ASSERT_EQ(converted_too_short.written_len, utf8_output_len);
    ASSERT(strncmp(utf8_output, "Tony! Toni! Toné!", utf8_output_len) == 0);

    aligned_free(data_long);
    aligned_free(utf8_output_long);

    aligned_free(data);
    aligned_free(utf8_output);

    PASS();
}

TEST test_utf8_to_utf32(void) {
    const char *data_str = (char *)"Tony! Toni! Toné!";
    size_t len = strlen((const char *)data_str);
    char *data = aligned_malloc(len, 32);
    memcpy(data, data_str, len);
    size_t utf32_output_len = len;
    uint32_t *utf32_output = aligned_malloc(utf32_output_len * sizeof(uint32_t), 32);

    utf_result_t converted = convert_utf8_to_utf32(data, len, utf32_output, utf32_output_len);
    ASSERT_EQ(converted.return_code, SIMDUTF_SUCCESS);
    ASSERT_EQ(converted.read_len, len);
    ASSERT_EQ(converted.written_len, 17);
    ASSERT_EQ(utf32_output[converted.written_len - 2], 233);

    printf("Did first utf8_to_utf32 test\n");
  
    const unsigned char *data_long_str = (unsigned char *)"we on a world tour nous sommes en tournée mondiale мы в мировом турне a wa lori irin-ajo agbaye είμαστε σε παγκόσμια περιοδεία jesteśmy w trasie dookoła świata míele xexeame katã ƒetsaɖiɖi aɖe dzi";
    size_t len_long = strlen((const char *)data_long_str);
    char *data_long = aligned_malloc(len_long, 32);
    memcpy(data_long, data_long_str, len_long);
    size_t utf32_output_len_long = len_long;
    uint32_t *utf32_output_long = aligned_malloc(utf32_output_len_long * sizeof(uint32_t), 32);
    utf_result_t converted_long = convert_utf8_to_utf32(data_long, len_long, utf32_output_long, utf32_output_len_long);
    ASSERT_EQ(converted_long.return_code, SIMDUTF_SUCCESS);
    ASSERT_EQ(converted_long.read_len, len_long);
    ASSERT_EQ(converted_long.written_len, 196);
    ASSERT_EQ(utf32_output_long[converted_long.written_len - 6], 598);

    memset(utf32_output, 0, utf32_output_len * sizeof(uint32_t));

    converted_long = convert_valid_utf8_to_utf32(data_long, len_long, utf32_output_long, utf32_output_len_long);
    ASSERT_EQ(converted_long.return_code, SIMDUTF_SUCCESS);
    ASSERT_EQ(converted_long.read_len, len_long);
    ASSERT_EQ(converted_long.written_len, 196);
    ASSERT_EQ(utf32_output_long[converted_long.written_len - 6], 598);

    aligned_free(data);
    aligned_free(utf32_output);
    aligned_free(data_long);
    aligned_free(utf32_output_long);

    PASS();
}


/* Add definitions that need to be in the test runner's main file. */
GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();      /* command-line options, initialization. */

    RUN_TEST(test_latin1_to_utf8);
    RUN_TEST(test_utf8_to_utf32);

    GREATEST_MAIN_END();        /* display results */
}