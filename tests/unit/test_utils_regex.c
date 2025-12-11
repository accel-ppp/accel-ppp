#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "utils.h"

int urandom_fd = -1;

void test_regex_match() {
    int errornumber;
    PCRE2_SIZE erroroffset;
    pcre2_code *re;
    
    const char *pattern = "eth.*";
    re = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
    if (!re) {
        fprintf(stderr, "PCRE2 compilation failed\n");
        return;
    }
    
    assert(u_match_regex(re, "eth0") == 1);
    assert(u_match_regex(re, "eth100") == 1);
    assert(u_match_regex(re, "lo") == 0);
    assert(u_match_regex(re, "wlan0") == 0);
    assert(u_match_regex(re, "ethernet") == 1);
    
    pcre2_code_free(re);
    printf("test_regex_match passed\n");
}

int main() {
    test_regex_match();
    return 0;
}

