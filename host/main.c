#include <stdio.h>
#include "aes_crypto.h"
#include "clearkey_platform.h"
#include "test_helpers.h"

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    statistics tests_stats;

    initialiseExternVariables();
    initialiseStats(&tests_stats);

    initialiseTZ();
    TestAll(&tests_stats);
    terminateTZ();

    printf("\n=====================================================================================================================================================\n");

    printf("Global statistics\n\n");

    printStatistics(tests_stats.passed, tests_stats.failed, tests_stats.total, tests_stats.time);

    printf("=====================================================================================================================================================\n\n");

    printf("\n");

    return 0;
}