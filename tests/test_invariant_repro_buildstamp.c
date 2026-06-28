#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

/* Import the actual function from the source file */
extern void repro_buildstamp(char *out, size_t outlen, const char *in);

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    /* Invariant: Buffer reads never exceed the declared length */
    const char *payloads[] = {
        "normal",                    /* Valid input */
        "A",                         /* Boundary: single char */
        "1234567890123456789012345678901234567890", /* 40 chars - likely exceeds buffer */
        "X",                         /* Another valid short input */
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" /* 100 chars - definitely exceeds */
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    
    for (int i = 0; i < num_payloads; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            /* Child process: run the actual function with test input */
            char buffer[32]; /* Small buffer to test overflow */
            memset(buffer, 0xAA, sizeof(buffer)); /* Fill with sentinel value */
            
            repro_buildstamp(buffer, sizeof(buffer), payloads[i]);
            
            /* Check that no bytes beyond buffer were touched */
            for (size_t j = sizeof(buffer); j < sizeof(buffer) + 16; j++) {
                if (*((char*)buffer + j) != 0xAA) {
                    _exit(1); /* Overflow detected */
                }
            }
            _exit(0); /* Success */
        } else {
            int status;
            waitpid(pid, &status, 0);
            ck_assert_msg(WIFEXITED(status) && WEXITSTATUS(status) == 0,
                         "Buffer overflow detected for payload: %s", payloads[i]);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}