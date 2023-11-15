/*
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <aes_crypto_ta.h>

#include "aes_crypto.h"
#include "clearkey_platform.h"
#include "logging.h"
#include "include/uapi/linux/ion.h"

#define MIN(a,b) (((a)<(b))?(a):(b))

#define CHECK_INVOKE2(res, orig, fn)              \
  do {                    \
    if (res != TEEC_SUCCESS)            \
      errx(1, "TEEC_InvokeCommand failed with code 0x%x " \
           "origin 0x%x", res, orig);         \
  } while(0)

#define CHECK_INVOKE(res, orig) CHECK_INVOKE2(res, orig, "TEE_InvokeCommand")

#define CHECK(res, fn)                  \
  do {                    \
    if (res != TEEC_SUCCESS)            \
      errx(1, fn " failed with code 0x%x ", res);     \
  } while(0)


/* Globals */

static TEEC_Context ctx;
static TEEC_Session sess;

static TEEC_SharedMemory g_key = {
  .size = CTR_AES_BLOCK_SIZE, /* 16byte key */
  .flags = TEEC_MEM_INPUT,
};

static TEEC_SharedMemory g_iv = {
  .size = CTR_AES_BLOCK_SIZE,
  .flags = TEEC_MEM_INPUT,
};

static void allocate_mem(void)
{
  TEEC_Result res;

  /* Allocate Initialization Vector shared with TEE */
  res = TEEC_AllocateSharedMemory(&ctx, &g_iv);
  CHECK(res, "TEEC_AllocateSharedMemory for IV");

  /* Allocate shared memory for key */
  res = TEEC_AllocateSharedMemory(&ctx, &g_key);
  CHECK(res,  "TEEC_AllocateSharedMemory for key");

}

/* increment counter (128-bit int) */
static void ctr128_inc(uint8_t *counter, uint32_t increment)
{
  uint16_t *c = (uint16_t *)(counter + 14);

  (*c) = htobe16(htobe16(*c) + increment);

}

static void free_mem(void)
{
  PR("Release IV shared memory...\n");
  TEEC_ReleaseSharedMemory(&g_iv);
  PR("Release key shared memory...\n");
  TEEC_ReleaseSharedMemory(&g_key);
}

/* Decrypt buffer */

int
TEE_AES_ctr128_encrypt(const unsigned char* in_data,
    unsigned char* out_data,
    uint32_t length, const char* key,
    unsigned char iv[CTR_AES_BLOCK_SIZE],
    unsigned char ecount_buf[CTR_AES_BLOCK_SIZE],
    unsigned int *num,
    uint32_t offset,
    bool secure) {
  TEEC_Result res;
  int secure_fd = -1;
  TEEC_Operation op;
  uint32_t err_origin;
  uint32_t n = 0;
  uint32_t blockOffset = *num;
  uint32_t len = length;
  TEEC_SharedMemory g_outm;

  // printf("offset: %d, blockOffset: %d, length: %d\n", offset, blockOffset, length);

  // printf("in_data: ");
  // for (int i = 0; i < length; i++)
  // {
  //   printf("0x%02x ", *((uint8_t *) in_data + i));
  // }
  // printf("\n");

  // printf("out_data: ");
  // for (int i = 0; i < length; i++)
  // {
  //   printf("0x%02x ", *((uint8_t *) out_data + i));
  // }
  // printf("\n");

  if (!key || !out_data || !num || !iv)
    return EINVAL;

  /* type cast to avoid warning of losing const qualifier */
  if (blockOffset > 0)
    memcpy((void *)(in_data + offset - blockOffset), ecount_buf, blockOffset);

  if (secure) {
    /* extract fd */
    secure_fd = clearkey_plat_get_mem_fd((void *)out_data);

#ifdef SDP_PROTOTYPE
    secure_fd = allocate_ion_buffer(length + blockOffset, ION_HEAP_TYPE_UNMAPPED);
#endif

    //g_outm.size = length;
    g_outm.flags = TEEC_MEM_OUTPUT;

    res = TEEC_RegisterSharedMemoryFileDescriptor(&ctx, &g_outm, secure_fd);
    CHECK(res, "TEEC_RegisterSharedMemory: g_outm (out buf) failed");
  }

  /* Store keys in shared memory */
  memcpy(g_key.buffer, key, CTR_AES_KEY_SIZE);
  memcpy(g_iv.buffer, iv, CTR_AES_IV_SIZE);

  if (!secure) {
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
				     TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_WHOLE,
				     TEEC_MEMREF_WHOLE);
  } else {
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
				     TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_WHOLE,
				     TEEC_MEMREF_WHOLE);
  }

  /* TA input buffer */
  op.params[PARAM_AES_ENCRYPTED_BUFFER_IDX].tmpref.buffer =
    (void *) (in_data + offset - blockOffset);

  op.params[PARAM_AES_ENCRYPTED_BUFFER_IDX].tmpref.size =
    length + blockOffset;

  // printf("TA input buffer: ");
  // for (int i = 0; i < op.params[PARAM_AES_ENCRYPTED_BUFFER_IDX].tmpref.size; i++)
  // {
  //   printf("0x%02x ", *((uint8_t *) op.params[PARAM_AES_ENCRYPTED_BUFFER_IDX].tmpref.buffer + i));
  // }
  // printf("\n");

  /* TA output buffer */
  if (!secure) {
    op.params[PARAM_AES_DECRYPTED_BUFFER_IDX].tmpref.buffer =
      (void *) (out_data + offset - blockOffset);

    op.params[PARAM_AES_DECRYPTED_BUFFER_IDX].tmpref.size =
      length + blockOffset;
  } else {
    op.params[PARAM_AES_DECRYPTED_BUFFER_IDX].memref.parent = &g_outm;
    op.params[PARAM_AES_DECRYPTED_BUFFER_IDX].memref.size =
      length + blockOffset;

    op.params[PARAM_AES_DECRYPTED_BUFFER_IDX].memref.offset =
      offset - blockOffset;
#ifdef SDP_PROTOTYPE
    op.params[PARAM_AES_DECRYPTED_BUFFER_IDX].memref.offset = 0;
#endif
  }

  /* TA IV */
  op.params[PARAM_AES_IV_IDX].memref.parent = &g_iv;
  op.params[PARAM_AES_IV_IDX].memref.size = CTR_AES_BLOCK_SIZE;
  /* TA Key */
  op.params[PARAM_AES_KEY].memref.parent = &g_key;
  op.params[PARAM_AES_KEY].memref.size =  CTR_AES_KEY_SIZE;

  res = TEEC_InvokeCommand(&sess, TA_AES_CTR128_ENCRYPT, &op,
         &err_origin);
  CHECK_INVOKE(res, err_origin);

#ifdef SDP_PROTOTYPE
  ion_map_and_memcpy(out_data + offset, length, secure_fd, blockOffset);
  close(secure_fd);
#endif

  // printf("TA output buffer: ");
  // for (int i = 0; i < op.params[PARAM_AES_DECRYPTED_BUFFER_IDX].tmpref.size; i++)
  // {
  //   printf("0x%02x ", *((uint8_t *) op.params[PARAM_AES_DECRYPTED_BUFFER_IDX].tmpref.buffer + i));
  // }
  // printf("\n");

  if(length + blockOffset > 16)
    len = length + blockOffset;

  while (len >= 16) {
    ctr128_inc(iv, 1);
    blockOffset = 0;
    len -= 16;
    n++;
  }

  if (len) {
    while (len--) {
      ++blockOffset;
    }
    memcpy(ecount_buf, in_data + offset + n*CTR_AES_BLOCK_SIZE, blockOffset);
  }
  *num = blockOffset;

  if (secure)
    TEEC_ReleaseSharedMemory(&g_outm);

  return 0;
}

int TEE_copy_secure_memory(const unsigned char* in_data, unsigned char* out_data,
			   uint32_t length, uint32_t offset)
{
  int secure_fd = -1;
  TEEC_Operation op;
  TEEC_Result res;
  uint32_t err_origin;
  TEEC_SharedMemory g_shm;
  TEEC_SharedMemory g_outm;

  g_shm.size = length;
  g_shm.buffer = (void *) (in_data + offset);
  g_shm.flags = TEEC_MEM_INPUT;

  res = TEEC_RegisterSharedMemory(&ctx, &g_shm);
  CHECK(res, "TEEC_RegisterSharedMemory: g_shm (in buf) failed");

  secure_fd = clearkey_plat_get_mem_fd((void *)out_data);
#ifdef SDP_PROTOTYPE
  secure_fd = allocate_ion_buffer(length, ION_HEAP_TYPE_UNMAPPED);
#endif

  g_outm.flags = TEEC_MEM_OUTPUT;
  res = TEEC_RegisterSharedMemoryFileDescriptor(&ctx, &g_outm, secure_fd);
  CHECK(res, "TEEC_RegisterSharedMemoryFileDescriptor: g_outm (out buf) failed");

  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT,
				   TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE,
				   TEEC_NONE);

  /* TA input buffer */
  op.params[PARAM_COPY_SECURE_MEMORY_SOURCE].memref.parent = &g_shm;
  op.params[PARAM_COPY_SECURE_MEMORY_SOURCE].memref.offset = 0;
  op.params[PARAM_COPY_SECURE_MEMORY_SOURCE].memref.size = length;
  /* TA output buffer */
  op.params[PARAM_COPY_SECURE_MEMORY_DESTINATION].memref.parent = &g_outm;
  op.params[PARAM_COPY_SECURE_MEMORY_DESTINATION].memref.offset = offset;
  op.params[PARAM_COPY_SECURE_MEMORY_DESTINATION].memref.size = length;

#ifdef SDP_PROTOTYPE
  /* no offset for sdp_protoype buffer */
  op.params[PARAM_COPY_SECURE_MEMORY_DESTINATION].memref.offset = 0;
#endif

  res = TEEC_InvokeCommand(&sess, TA_COPY_SECURE_MEMORY, &op,
         &err_origin);
  CHECK_INVOKE(res, err_origin);

#ifdef SDP_PROTOTYPE
  /* sdp_protoype test code assumes memory isn't actually secure */
  ion_map_and_memcpy(out_data + offset, length, secure_fd, 0);
  close(secure_fd);
#endif

  TEEC_ReleaseSharedMemory(&g_shm);
  TEEC_ReleaseSharedMemory(&g_outm);

  return 0;
}

int
TEE_AES_ctr128_encrypt_secure(const unsigned char* in_data,
    unsigned char* out_data,
    const sub_sample_t* samples,
    uint32_t samples_size,
    const char* key,
    unsigned char iv[CTR_AES_BLOCK_SIZE],
    uint32_t *length)
{
    TEEC_SharedMemory shm;
    TEEC_Result res;
    uint32_t err_origin;
    int memfd = -1;
    TEEC_Operation op;
    char key_and_iv[CTR_AES_KEY_SIZE + CTR_AES_IV_SIZE];
    /*
     * Retrieve SDP memory handles -- leave error checking in
     * TEEC_RegisterSharedMemoryFileDescriptor.
     */
    memfd = clearkey_plat_get_mem_fd((void *)out_data);

    shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    res = TEEC_RegisterSharedMemoryFileDescriptor(&ctx, &shm, memfd);
    if (res != TEEC_SUCCESS)
        return -1;

    /* First input buffer as tempref */
    op.params[0].tmpref.buffer = (void *)in_data;
    op.params[0].tmpref.size = *length;
    /* Output buffer as SDP */
    op.params[1].memref.parent = &shm;
    op.params[1].memref.size = *length;
    op.params[1].memref.offset = 0;
    /* Frames */
    op.params[2].tmpref.buffer = (void *)samples;
    op.params[2].tmpref.size = samples_size;
    if (key) {
        memcpy(key_and_iv, key, CTR_AES_KEY_SIZE);
        memcpy(&key_and_iv[CTR_AES_KEY_SIZE], iv, CTR_AES_IV_SIZE);
    } else
        memset(key_and_iv, 0, sizeof(key_and_iv));

    op.params[3].tmpref.buffer = (void *)key_and_iv;
    op.params[3].tmpref.size = sizeof(key_and_iv);

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_PARTIAL_OUTPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT);

    res = TEEC_InvokeCommand(&sess, TA_AES_CTR128_SECURE_ENCRYPT,
                             &op, &err_origin);
    TEEC_ReleaseSharedMemory(&shm);
    CHECK_INVOKE(res, err_origin);
    return memfd;
}

int TEE_crypto_init()
{
  TEEC_Result res;
  TEEC_UUID uuid = TA_AES_DECRYPTOR_UUID;
  uint32_t err_origin;

  if(g_iv.buffer)
    return TEEC_SUCCESS;

  res = TEEC_InitializeContext(NULL, &ctx);

  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

  res = TEEC_OpenSession(&ctx, &sess, &uuid,
             TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
      res, err_origin);

  if (!g_iv.buffer || !g_key.buffer)
    allocate_mem();

 return res;
}

int
TEE_crypto_close() {

  if(!g_iv.buffer)
    return TEEC_SUCCESS;

  free_mem();

  TEEC_CloseSession(&sess);
  TEEC_FinalizeContext(&ctx);
  return TEEC_SUCCESS;
}
