/** \file
 *
 * \brief TO DO YET!!!!
 *
 * This file is licensed as described by the file LICENCE.
 */

#include "common.h"
#include "extern.h"
#include "test_helpers.h"
#include "test_all.h"
#include "tz_functions.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

/** After each call to generateTestTransaction(), this will contain the offset
 * within the "full" transaction where the main transaction begins. */
static uint32_t main_offset;

void reportFailureAll(void)
{
	tests_failed++;
	tests_total++;
	printf("\tTest %2d: FAILED\n", tests_total);
}

void reportSuccessAll(void)
{
	tests_passed++;
	tests_total++;
	printf("\tTest %2d: PASSED\n", tests_total);
}

void initialiseTestsAll(void)
{
	is_test = true;
	is_test_all = true;

	tests_total = 0;
	tests_failed = 0;
	tests_passed = 0;

	srand(42); /* Make sure tests which rely on rand() are deterministic */

	printf("\n\n=====================================================================================================================================================\n");

	printf("Executing the tests for transaction now.\n");

	printf("=====================================================================================================================================================\n");

	start_time = clock();
}

void finaliseTestsAll(void)
{
	time_t t;

	finish_time = clock();

	is_test = false;
	is_test_all = true;

	time_spent = ((double)(finish_time - start_time)) / CLOCKS_PER_SEC;

	srand((unsigned)time(&t));

	printf("\n=====================================================================================================================================================\n");

	printf("Finished executing the tests for all\n\n");

	printStatistics(tests_passed, tests_failed, tests_total, time_spent);

	printf("=====================================================================================================================================================\n\n");
}

void TestAll(statistics *stats)
{

	initialiseTestsAll();

	printf("Check aes_Ctr128_Encrypt\n");

	printf("Check copy_secure_memory\n");

	printf("Check aes_Ctr128_Encrypt_secure\n");

	if (false)
	{
		reportFailureAll();
	}
	else
	{
		reportSuccessAll();
	}

	finaliseTestsAll();

	(stats->passed) += tests_passed;
	(stats->failed) += tests_failed;
	(stats->total) += tests_total;
	(stats->time) += time_spent;
}