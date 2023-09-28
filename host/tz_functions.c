/** \file
 *
 * \brief Consists in all the Client Application functions that interact with
 * Trusted Applications.
 *
 * Manages functions related with the initialization and closing of sessions
 * and contexts as well all the other functions that invoke some command upon
 * trusted applications in the secure world.
 *
 * This file is licensed as described by the file LICENCE.
 */

#include "common.h"
#include "tz_functions.h"
#include "aes_crypto_ta.h"

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <tee_client_api.h>

/* TODO CONFIRM THAT WHEN TESTING IS NOT INCLUDED ALL THE FUNCTIONS ARE NOT COMPILED */

/** Used to contain control information related to the context between the CA
 * and the TEE. */
TEEC_Context context;

/** Used to contain control information related to the session between the CA
 * and the TA */
TEEC_Session session;

/**
 * Initializes a new TEE context and opens a new session with all trusted
 * applications.
 * \warning This functions only initializes, in the end it is necessary to call
 *          terminateTZ() for a clean exit.
 */
void initialiseTZ(void)
{
    TEEC_Result result = TEEC_SUCCESS;
    TEEC_UUID uuid = TA_AES_DECRYPTOR_UUID;
    uint32_t error_origin;

    /*
     * Initialize a new TEE Context, forming a connection between this Client
     * Application and the TEE.
     */
    result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext failed with code 0x%x", result);

    /*
     * Open a new session between the Client Application and the Trusted
     * Application (identified by a UUID).
     * Currently the only connectionMethod supported is TEEC_LOGIN_PUBLIC.
     */
    result = TEEC_OpenSession(
        &context,
        &session,
        &uuid,
        TEEC_LOGIN_PUBLIC,
        NULL,
        NULL,
        &error_origin);
    if (result != TEEC_SUCCESS)
    {
        /*
         * The context should be finalized when the connection with the TEE is
         * no longer required, allowing resources to be released. This function
         * must only be called when all session inside this TEE context have
         * been closed and all shared memory blocks have been released.
         */
        TEEC_FinalizeContext(&context);

        errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", result, error_origin);
    }

    /* Initialize the operation handles in the Trusted Application */
    result = TEEC_InvokeCommand(
        &session,
        TA_INITIALIZE_HANDLERS,
        NULL,
        &error_origin);
    if (result != TEEC_SUCCESS)
    {
        /*
         * The context should be finalized when the connection with the TEE is
         * no longer required, allowing resources to be released. This function
         * must only be called when all session inside this TEE context have
         * been closed and all shared memory blocks have been released.
         */
        TEEC_FinalizeContext(&context);

        errx(1, "TEEC_InvokeCommand for TA_INITIALIZE_HANDLERS failed with code 0x%x origin 0x%x", result, error_origin);
    }
}

/**
 * Finalizes the TEE context and closes all sessions opened with all the
 * trusted applications.
 * \return TEEC_SUCCESS in case of success otherwise returns the result
 *         received from the failed operation. The information about all
 *         possible returns is present in TEE Client API Specification - 4.4.2.
 * \warning Should only be called if initialiseTZ() was called first,
 */
void terminateTZ(void)
{
    TEEC_Result result = TEEC_SUCCESS;
    uint32_t error_origin;

    result = TEEC_InvokeCommand(
        &session,
        TA_FINALIZE_HANDLERS,
        NULL,
        &error_origin);
    if (result != TEEC_SUCCESS)
        fprintf(stderr, "TEEC_InvokeCommand for TA_FINALIZE_HANDLERS failed with code 0x%x origin 0x%x\n", result, error_origin);

    /*
     * Closes the session opened with the Trusted Application. All the commands
     * within the session must have completed before calling this function
     */
    TEEC_CloseSession(&session);

    /*
     * The context should be finalized when the connection with the TEE is
     * no longer required, allowing resources to be released. This function
     * must only be called when all session inside this TEE context have
     * been closed and all shared memory blocks have been released.
     */
    TEEC_FinalizeContext(&context);
}

void copySecureMemoryTZ(void)
{
    ;
}

void copySecureMemoryTZ(void)
{
    ;
}

void copySecureMemoryTZ(void)
{
    ;
}
