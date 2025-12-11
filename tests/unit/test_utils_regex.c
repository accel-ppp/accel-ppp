#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "utils.h"
#include "log.h" // Include log.h for error logging in test

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

void test_compile_interface_regex() {
    pcre2_code *re;
    const char *endptr;

    // Test valid compilation
    re = u_compile_interface_regex("re:eth.*,other_opt", "re:", &endptr);
    assert(re != NULL);
    assert(u_match_regex(re, "eth0") == 1);
    assert(strcmp(endptr, ",other_opt") == 0);
    pcre2_code_free(re);

    // Test without additional options
    re = u_compile_interface_regex("re:lo.*", "re:", &endptr);
    assert(re != NULL);
    assert(u_match_regex(re, "lo") == 1);
    assert(strcmp(endptr, "") == 0);
    pcre2_code_free(re);

    // Test invalid prefix (should return NULL and log error)
    re = u_compile_interface_regex("fo:eth.*", "re:", &endptr);
    assert(re == NULL);

    // Test invalid regex pattern (should return NULL and log error)
    re = u_compile_interface_regex("re:et(h.*", "re:", &endptr);
    assert(re == NULL);

    printf("test_compile_interface_regex passed\n");
}

// This test function covers real-world examples of interface name matching
// using regular expressions in accel-ppp, particularly for complex scenarios
// involving VLANs (single or QinQ). This serves both as a regression test
// to ensure future changes do not break existing regex matching logic and
// as a documentation/example for users to understand how these regexes
// should be crafted for accel-ppp's interface definitions.
void test_real_world_examples() {
    pcre2_code *re;

    // 1. Match any VLAN on eth0: eth0.N
    // Regex: ^eth0\.[0-9]+$
    // Note: In C strings backslash is escaped, so \\.
    re = u_compile_interface_regex("re:^eth0\\.[0-9]+$", "re:", NULL);
    assert(re != NULL);
    assert(u_match_regex(re, "eth0.10") == 1);
    assert(u_match_regex(re, "eth0.100") == 1);
    assert(u_match_regex(re, "eth0.4095") == 1);
    assert(u_match_regex(re, "eth0") == 0);       // Missing VLAN
    assert(u_match_regex(re, "eth1.10") == 0);    // Wrong interface
    assert(u_match_regex(re, "eth0.10.20") == 0); // QinQ should not match simple VLAN regex
    pcre2_code_free(re);

    // 2. Match QinQ (Double VLAN) on eth0: eth0.N.M
    // Regex: ^eth0\.[0-9]+\.[0-9]+$
    re = u_compile_interface_regex("re:^eth0\\.[0-9]+\\.[0-9]+$", "re:", NULL);
    assert(re != NULL);
    assert(u_match_regex(re, "eth0.10.20") == 1);
    assert(u_match_regex(re, "eth0.100.200") == 1);
    assert(u_match_regex(re, "eth0.10") == 0);
    pcre2_code_free(re);

    // 3. Match specific VLAN range (100-199) on eth0
    // Regex: ^eth0\.1[0-9][0-9]$
    re = u_compile_interface_regex("re:^eth0\\.1[0-9][0-9]$", "re:", NULL);
    assert(re != NULL);
    assert(u_match_regex(re, "eth0.100") == 1);
    assert(u_match_regex(re, "eth0.150") == 1);
    assert(u_match_regex(re, "eth0.199") == 1);
    assert(u_match_regex(re, "eth0.200") == 0);
    assert(u_match_regex(re, "eth0.099") == 0);
    pcre2_code_free(re);

    // 4. Match specific set of VLANs (10, 20, 30)
    // Regex: ^eth0\.(10|20|30)$
    re = u_compile_interface_regex("re:^eth0\\.(10|20|30)$", "re:", NULL);
    assert(re != NULL);
    assert(u_match_regex(re, "eth0.10") == 1);
    assert(u_match_regex(re, "eth0.20") == 1);
    assert(u_match_regex(re, "eth0.30") == 1);
    assert(u_match_regex(re, "eth0.40") == 0);
    assert(u_match_regex(re, "eth0.100") == 0);
    pcre2_code_free(re);

    // 5. QinQ: Match any inner VLAN on specific outer VLAN (100)
    // Regex: ^eth0\.100\.[0-9]+$
    re = u_compile_interface_regex("re:^eth0\\.100\\.[0-9]+$", "re:", NULL);
    assert(re != NULL);
    assert(u_match_regex(re, "eth0.100.1") == 1);
    assert(u_match_regex(re, "eth0.100.200") == 1);
    assert(u_match_regex(re, "eth0.200.200") == 0); // Wrong outer VLAN
    pcre2_code_free(re);

    printf("test_real_world_examples passed\n");
}

int main() {
    test_regex_match();
    test_compile_interface_regex();
    test_real_world_examples();
    return 0;
}

