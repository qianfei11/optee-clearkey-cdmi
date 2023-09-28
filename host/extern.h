/** \file
 *
 * \brief Declaration of global variables.
 *
 * Most of this variables are used for testing purposes. This is a way to allow
 * the variables to be available both in the respective .c file and respective
 * .c test file.
 *
 * This file is licensed as described by the file LICENCE.
 */

#ifndef EXTERN_H_INCLUDED
#define EXTERN_H_INCLUDED

#include "common.h"

/** Variable used to indicate that the actual execution of the wallet is being
 * done to test some kind of functions and as such with this set to true it is
 * possible to use/avoid some specific instructions like re-seed the random
 * generator or replace the OTP generated with a static one to easy the
 * testing. */
extern bool is_test;

extern bool is_test_all;

/** Hack to allow test to access derived chain code. This is needed for the
 * sipa test cases. */
extern uint8_t test_chain_code[32];

/** Set this to true to stop sanitiseNonVolatileStorage() from
 * updating the persistent entropy pool. This is necessary for some test
 * cases which check where sanitiseNonVolatileStorage() writes; updates
 * of the entropy pool would appear as spurious writes to those test cases.
 */
extern bool suppress_set_entropy_pool;

/** Use this to stop nonVolatileWrite() from logging all non-volatile writes
 * to stdout. */
extern bool suppress_write_debug_info;

/** Index into #version_field_writes where next entry will be written. */
extern int version_field_index;

/** Cache of number of wallets that can fit in non-volatile storage. This will
 * be 0 if a value hasn't been calculated yet. This is set by
 * getNumberOfWallets(). */
extern uint32_t num_wallets;

/** Where the transaction parser is within a transaction. 0 = first byte,
 * 1 = second byte etc. */
extern uint32_t transaction_data_index;

/** The total length of the transaction being parsed, in number of bytes. */
extern uint32_t transaction_length;

/** Index into #version_field_writes where next entry will be written. */
extern int version_field_index;

/** Number of outputs seen. */
extern int num_outputs_seen;

/** This will be called during stream tests for recording the response (byte by
 * byte) of the current test stream. It is used because it facilitates the
 * response generated with the one that was expected.
 * \param byte The byte to be recorded. It corresponds to the byte sent as
 *             response to the host.
 */
extern void writeResponseByte(uint8_t byte);

/** This functions is used to initialize some of the extern variables described
 * in extern.h.
 */
extern void initialiseExternVariables(void);

/** This will be called by sanitiseNonVolatileStorage() every time it
 * clears the version field of a wallet. This is used to test whether
 * sanitiseNonVolatileStorage() is clearing version fields properly.
 * \param address The address (in non-volatile storage) where the cleared
 *                version field is.
 */
extern void logVersionFieldWrite(uint32_t address);

/** Clear the list of version field writes. */
extern void clearVersionFieldWriteLog(void);

extern int tests_passed;
extern int tests_failed;
extern int tests_total;
extern clock_t start_time;
extern clock_t finish_time;
extern double time_spent;

#endif
