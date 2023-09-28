/** \file
 *
 * \brief It contains global variables definitions and related functions.
 *
 * The variables declared here are defined in extern.h and this is because
 * these variables are used as global variables. The most of them  are used
 * to be shared between a file and its respective test file and others are
 * used to indicate if a test (and which one) is being performed.
 *
 * This file is licensed as described by the file LICENCE.
 */

#include "common.h"
#include "extern.h"

int version_field_index;
int num_outputs_seen;
bool is_test;
bool is_test_all;
int tests_passed;
int tests_failed;
int tests_total;
clock_t start_time;
clock_t finish_time;
double time_spent;

/** Initialize some of the external variables. */
void initialiseExternVariables(void)
{
  is_test = false;
  is_test_all = false;
}
