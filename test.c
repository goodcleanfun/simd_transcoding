#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "greatest/greatest.h"
#include "aligned/aligned.h"
#include "latin1_to_utf8.h"

TEST test_latin1_to_utf8(void) {
    const char *data_str = (char *)"Tony! Toni! Ton\xe9!";
    size_t len = strlen((const char *)data_str);
    char *data = aligned_malloc(len, 32);
    memcpy(data, data_str, len);
    size_t utf8_output_len = len + 1;
    char *utf8_output = aligned_malloc(utf8_output_len, 32);

    size_t converted = convert_latin1_to_utf8(data, len, utf8_output, utf8_output_len);
    ASSERT_EQ(converted, len);
    ASSERT(strncmp(utf8_output, "Tony! Toni! Toné!", utf8_output_len) == 0);

    const char *data_str_long = (char *)"Tony! Toni! Ton\xe9! Tony! Toni! Ton\xe9! Tony! Toni! Ton\xe9! Tony! Toni! Ton\xe9!";
    size_t len_long = strlen((const char *)data_str_long);
    char *data_long = aligned_malloc(len_long, 32);
    memcpy(data_long, data_str_long, len_long);

    size_t utf8_output_len_long = len_long + 1;
    char *utf8_output_long = aligned_malloc(utf8_output_len_long, 32);

    size_t converted_long = convert_latin1_to_utf8(data_long, len_long, utf8_output_long, utf8_output_len_long);
    ASSERT_EQ(converted_long, len_long);
    ASSERT(strncmp(utf8_output_long, "Tony! Toni! Toné! Tony! Toni! Toné! Tony! Toni! Toné! Tony! Toni! Toné!", utf8_output_len_long) == 0);

    size_t converted_too_short = convert_latin1_to_utf8(data_long, len_long, utf8_output, utf8_output_len);
    ASSERT_EQ(converted_too_short, len);
    ASSERT(strncmp(utf8_output, "Tony! Toni! Toné!", utf8_output_len) == 0);

    aligned_free(data_long);
    aligned_free(utf8_output_long);

    aligned_free(data);
    aligned_free(utf8_output);

    PASS();
}


/* Add definitions that need to be in the test runner's main file. */
GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();      /* command-line options, initialization. */

    RUN_TEST(test_latin1_to_utf8);

    GREATEST_MAIN_END();        /* display results */
}