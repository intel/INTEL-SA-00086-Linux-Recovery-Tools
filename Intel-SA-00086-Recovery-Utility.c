/******************************************************************************
 * Intel-SA-00086-Recovery-Utility.c
 * 
 * BSD LICENSE
 *
 * Copyright (C) 2003-2012, 2018 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <getopt.h>
#include <limits.h>

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <curl/curl.h>

#include <tcti/tcti_device.h>
#include <tcti/tcti-tabrmd.h>
#include <sapi/tpm20.h>

#define TCTI_DEVICE_DEFAULT_PATH "/dev/tpm0"

#define DEFAULT_PERSISTENT_HANDLE_FOR_EK 0x81010001

#define FATAL_ERROR -99

#define CHANGE_ENDIAN_DWORD(p) ( ChangeEndianDword(p) )

typedef struct intel_ptt_utility_ctx intel_ptt_utility_ctx;
struct intel_ptt_utility_ctx {
    TSS2_SYS_CONTEXT* sapi_ctx;
    TPM_HANDLE handle_ek;
    bool flag_getek ;
    unsigned char *EK;
    bool flag_getek_cert;
    unsigned char *EK_cert;
    bool flag_is_ptt;
    bool flag_is_EPS_from_PTT;
    bool flag_check_nv;
    bool flag_read_nv;
    unsigned char *nv_index_input;
    bool flag_nv_out;
    unsigned char *nv_data_output_file;
    bool flag_make_persisitent;
};

TSS2_TCTI_CONTEXT* tcti_tabrmd_init (void) {
    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2_RC rc;
    size_t size;

    rc = tss2_tcti_tabrmd_init(NULL, &size);
    if (rc != TSS2_RC_SUCCESS) {
        printf("ERROR: Failed getting TABRMD TCTI context size");
        return NULL;
    }
    tcti_ctx = (TSS2_TCTI_CONTEXT*)calloc (1, size);
    if (tcti_ctx == NULL) {
        printf("ERROR: Failed TABRMD TCTI context allocation: %s",
                 strerror (errno));
        return NULL;
    }
    rc = tss2_tcti_tabrmd_init (tcti_ctx, &size);
    if (rc != TSS2_RC_SUCCESS) {
        printf("ERROR: Failed TABRMD TCTI context initialization");
        free (tcti_ctx);
        return NULL;
    }
    return tcti_ctx;
}

TSS2_SYS_CONTEXT* sapi_ctx_init (TSS2_TCTI_CONTEXT *tcti_ctx) {
    TSS2_SYS_CONTEXT *sapi_ctx;
    TSS2_RC rc;
    size_t size;
    TSS2_ABI_VERSION abi_version = {
        .tssCreator = TSSWG_INTEROP,
        .tssFamily  = TSS_SAPI_FIRST_FAMILY,
        .tssLevel   = TSS_SAPI_FIRST_LEVEL,
        .tssVersion = TSS_SAPI_FIRST_VERSION,
    };

    size = Tss2_Sys_GetContextSize (0);
    sapi_ctx = (TSS2_SYS_CONTEXT*)calloc (1, size);
    if (sapi_ctx == NULL) {
        printf ("ERROR: Failed SAPI context buffer allocation.");
        return NULL;
    }
    rc = Tss2_Sys_Initialize (sapi_ctx, size, tcti_ctx, &abi_version);
    if (rc != TSS2_RC_SUCCESS) {
        printf ("ERROR: Failed SAPI context initialization: 0x%x\n", rc);
        free (sapi_ctx);
        return NULL;
    }
    return sapi_ctx;
}

int save_data_to_file(const char *fileName, UINT8 *buf, UINT16 size) {
    FILE *f;
    UINT16 count = 1;
    if (fileName == NULL || buf == NULL || size == 0)
        return -1;

    f = fopen(fileName, "wb+");
    if (f == NULL) {
        printf("ERROR: File(%s) open error.\n", fileName);
        return -2;
    }

    while (size > 0 && count > 0) {
        count = fwrite(buf, 1, size, f);
        size -= count;
        buf += count;
    }

    if (size > 0) {
        printf("ERROR: Failed file write operation.\n");
        fclose(f);
        return -3;
    }

    fclose(f);
    return 0;
}

UINT32 ChangeEndianDword( UINT32 p )
{
    return( ((const UINT32)(((p)& 0xFF) << 24))    | \
          ((const UINT32)(((p)& 0xFF00) << 8))   | \
          ((const UINT32)(((p)& 0xFF0000) >> 8)) | \
          ((const UINT32)(((p)& 0xFF000000) >> 24)));
}

int get_current_ek(intel_ptt_utility_ctx *ctx) {
    //RESPONSE
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    //COMMAND
    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM_RS_PW,
        //.nonce.t.size = 0,
        .hmac.t.size = 0,
        .sessionAttributes.val = 0
    };
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData = {
        .cmdAuths = &sessionDataArray[0],
        .cmdAuthsCount = 1
    };

    TPM2B_PUBLIC inPublic = {
        .t.publicArea = {
            .nameAlg = TPM_ALG_SHA256,
            .authPolicy.t.size = 32,
            .type = TPM_ALG_RSA,
            .unique.rsa.t.size = 256,
            .objectAttributes = {
                .val = 0,
                .restricted = 1,
                .userWithAuth = 0,
                .adminWithPolicy = 1,
                .sign = 0,
                .decrypt = 1,
                .fixedTPM = 1,
                .fixedParent = 1,
                .sensitiveDataOrigin = 1,
            },
            .parameters.rsaDetail = {
                .scheme.scheme = TPM_ALG_NULL,
                .keyBits = 2048,
                .exponent = 0,
                .symmetric = {
                    .algorithm = TPM_ALG_AES,
                    .keyBits.aes = 128,
                    .mode.aes = TPM_ALG_CFB,
                },
            },
        }
    };
    BYTE authPolicy[] = { 0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A,
            0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E,
            0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69,
            0xAA };
    uint8_t i;
    for(i=0; i<32; i++) {
        inPublic.t.publicArea.authPolicy.t.buffer[i] = authPolicy[i];
    }

    TPML_PCR_SELECTION creationPCR = {
        .count = 0
    };
    TPM2B_SENSITIVE_CREATE inSensitive = {
            { sizeof(TPM2B_SENSITIVE_CREATE) - 2, } };
    TPM2B_DATA outsideInfo = { { 0, } };
    TPM2B_NAME name = { { sizeof(TPM2B_NAME) - 2, } };
    TPM2B_PUBLIC outPublic = { { 0, } };
    TPM2B_CREATION_DATA creationData = { { 0, } };
    TPM2B_DIGEST creationHash = { { sizeof(TPM2B_DIGEST) - 2, } };
    TPMT_TK_CREATION creationTicket = { 0, };

    UINT32 rval = Tss2_Sys_CreatePrimary(ctx->sapi_ctx, TPM_RH_ENDORSEMENT,
        &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
        &ctx->handle_ek, &outPublic, &creationData, &creationHash,
        &creationTicket, &name, &sessionsDataOut);
    if (rval != TPM_RC_SUCCESS) {
        printf("\nERROR: Failed TPM2_CreatePrimary. TPM Error:0x%x\n", rval);
        return FATAL_ERROR;
    }
    if (save_data_to_file(ctx->EK, (UINT8 *) &outPublic, sizeof(outPublic))) {
        printf("\nERROR: Failed to save EK pub key into file(%s)\n", ctx->EK);
        return 1;
    }

    return 0;
}

unsigned char *hash_EK_public_key(intel_ptt_utility_ctx *ctx) {
    FILE *fp;
    unsigned char EKpubKey[259];
    unsigned char *hash = (unsigned char*) malloc(SHA256_DIGEST_LENGTH);
    if (hash == NULL) {
        printf("ERROR: Failed buffer allocation for storing hash.\n");
        goto error_hash_EK_public_key;
    }
    int read_cnt = 0;
    fp = fopen(ctx->EK, "rb");
    if (fp == NULL) {
        printf("ERROR: Failed file open operation\n");
        goto error_hash_EK_public_key;
    } else {
        fseek(fp, 0x66, 0);
        read_cnt = fread(EKpubKey, 1, 256, fp);
    }
    fclose(fp);
    EKpubKey[256] = 0x01;
    EKpubKey[257] = 0x00;
    EKpubKey[258] = 0x01; //Exponent
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, EKpubKey, sizeof(EKpubKey));
    SHA256_Final(hash, &sha256);
    return hash;

error_hash_EK_public_key:
    free(hash);
    return NULL;
}

char *base64_encode(const unsigned char* buffer) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    if (buffer == NULL) {
        printf("ERROR: HashEKPublicKey returned null");
        return NULL;
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, SHA256_DIGEST_LENGTH);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);

    char *b64text = bufferPtr->data;
    size_t len = bufferPtr->length;

    size_t i;
    for (i = 0; i < len; i++) {
        if (b64text[i] == '+') {
            b64text[i] = '-';
        }
        if (b64text[i] == '/') {
            b64text[i] = '_';
        }
    }

    char *final_string = NULL;

    CURL *curl = curl_easy_init();
    if (curl) {
        char *output = curl_easy_escape(curl, b64text, len);
        if (output) {
            final_string = strdup(output);
            curl_free(output);
        }
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    BIO_free_all(bio);

    return final_string;
}

int retrieve_endorsement_key_certificate(intel_ptt_utility_ctx *ctx, char *b64h) {
    if (b64h == NULL) {
        printf("ERROR: Base64Encode of EKpublic hash cannot be null.\n");
        return 1;
    }
    const char *EKserverAddr = "https://ekop.intel.com/ekcertservice/";
    printf("\nRetrieving Endorsement Credential Certificate from the TPM "
        "Manufacturer EK Provisioning Server.\n");
    char *weblink = (char*) malloc(1 + strlen(b64h) + strlen(EKserverAddr));
    if (weblink == NULL) {
        printf("ERROR: Failed buffer allocation for server address name.\n");
        return 1;
    }
    size_t len = 1 + strlen(b64h) + strlen(EKserverAddr);
    memset(weblink, 0, len);
    snprintf(weblink, len, "%s%s", EKserverAddr, b64h);
    printf("%s\n", weblink);
    CURL *curl;
    CURLcode res;

    FILE *respfile = fopen(ctx->EK_cert, "wb");
    if (respfile == NULL) {
        printf("ERROR: Failed to create EK certificate file.\n");
        free(weblink);
        return 1;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (curl) {
        /*
         * should not be used - Used only on platforms with older CA certificates.
         */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);

        curl_easy_setopt(curl, CURLOPT_URL, weblink);
        /*
         * adding to handle 404 errors.
         */
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, weblink);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, respfile);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, respfile);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "\nERROR: Failed curl_easy_perform(): %s\n",
                    curl_easy_strerror(res));
            free(weblink);
            fclose(respfile);
            return 1;
        }
        curl_easy_cleanup(curl);
    }
    fclose(respfile);
    curl_global_cleanup();
    printf("\n");
    free(weblink);
    return 0;
}

bool is_PTT(intel_ptt_utility_ctx *ctx) {
    char manuID[5] = "    ";
    char *manuIDPtr = &manuID[0];
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA capability_data;

    UINT32 rval = Tss2_Sys_GetCapability(ctx->sapi_ctx, 0, TPM_CAP_TPM_PROPERTIES,
            TPM_PT_MANUFACTURER, 1, &more_data, &capability_data, 0);
    if (rval != TPM_RC_SUCCESS) {
        return FATAL_ERROR;
    }
    *((UINT32 *) manuIDPtr) = CHANGE_ENDIAN_DWORD(
            capability_data.data.tpmProperties.tpmProperty[0].value);
    if (0 == strcmp(manuID, "INTC")) {
        printf("TPM Manufacturer: INTC or Intel (R) PTT\n");
        return true;
    } else {
        printf("ERROR: TPM Manufacturer is not INTC.\n");
        return false;
    }
}

bool is_EPS_PTT_generated(intel_ptt_utility_ctx *ctx) {
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA capability_data;
    UINT32 rval = Tss2_Sys_GetCapability(ctx->sapi_ctx, 0, TPM_CAP_TPM_PROPERTIES,
            TPM_PT_PERMANENT, 1, &more_data, &capability_data, 0);
    if (rval != TPM_RC_SUCCESS) {
        printf("ERROR: TPM communication error.\n");
        return false;
    }

    UINT32 parseVal = capability_data.data.tpmProperties.tpmProperty[0].value;
    if (parseVal & 0x400) {
        printf("EPS is generated by Intel (R) PTT\n");
        return true;
    } else {
        printf("EPS is generated by Manufacturer\n");
        return false;
    }
}

int check_if_nv_index_defined_and_written (intel_ptt_utility_ctx *ctx) {
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA capability_data;
    UINT32 rval = Tss2_Sys_GetCapability(ctx->sapi_ctx, 0, TPM_CAP_HANDLES,
            CHANGE_ENDIAN_DWORD(TPM_HT_NV_INDEX), TPM_PT_NV_INDEX_MAX,
            &more_data, &capability_data, 0);
    if (rval != TPM_RC_SUCCESS) {
        printf("\nERROR: GetCapability TPM Error:0x%x\n", rval);
        return FATAL_ERROR;
    }
    bool index_present = false;
    UINT32 i;
    for (i = 0; i < capability_data.data.handles.count; i++) {
        if (capability_data.data.handles.handle[i]
                == strtoul(ctx->nv_index_input, 0, 16)) {
            index_present = true;
            break;
        }
    }
    if (index_present) {
        //Checking if nv index is written at all to be usable in this app context
        TPM2B_NAME nv_name = { { sizeof(TPM2B_NAME) - 2, } };
        TPM2B_NV_PUBLIC nv_public = { { 0, } };
        rval = Tss2_Sys_NV_ReadPublic(ctx->sapi_ctx,
            strtoul(ctx->nv_index_input, 0, 16), 0, &nv_public, &nv_name,0);
        if (rval != TPM_RC_SUCCESS) {
            printf("\nERROR: Failed NVReadPublic TPM Error: 0x%0x\n\n", rval);
            return FATAL_ERROR;
        }
        if (nv_public.t.nvPublic.attributes.val & (1 << 29)) {
            return 0;
        } else {
            printf("ERROR: NV Index is not written\n");
            return 1;
        }
    } else {
        return 1;
    }
}

int make_current_ek_persistent (intel_ptt_utility_ctx *ctx) {
    //RESPONSE
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    //COMMAND
    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM_RS_PW,
        //.nonce.t.size = 0,
        .hmac.t.size = 0,
        .sessionAttributes.val = 0
    };
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData = {
        .cmdAuths = &sessionDataArray[0],
        .cmdAuthsCount = 1
    };

    UINT32 rval = Tss2_Sys_EvictControl(ctx->sapi_ctx, TPM_RH_OWNER,
        DEFAULT_PERSISTENT_HANDLE_FOR_EK, &sessionsData,
        DEFAULT_PERSISTENT_HANDLE_FOR_EK, &sessionsDataOut);

    rval = Tss2_Sys_EvictControl(ctx->sapi_ctx, TPM_RH_OWNER,
        ctx->handle_ek, &sessionsData, DEFAULT_PERSISTENT_HANDLE_FOR_EK,
        &sessionsDataOut);
    if (rval != TPM_RC_SUCCESS) {
        printf("\nERROR: EvictControl TPM Error:0x%x\n", rval);
        return FATAL_ERROR;
    } 
    return 0;
}

int read_nv_index_to_file (intel_ptt_utility_ctx *ctx) {
    //RESPONSE
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    sessionDataOutArray[0] = &sessionDataOut;
    TSS2_SYS_RSP_AUTHS sessionsDataOut;
    sessionsDataOut.rspAuths = &sessionDataOutArray[0];
    sessionsDataOut.rspAuthsCount = 1;

    //COMMAND
    TPMS_AUTH_COMMAND sessionData = {
        .sessionHandle = TPM_RS_PW,
        //.nonce.t.size = 0,
        .hmac.t.size = 0,
        .sessionAttributes.val = 0
    };
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    sessionDataArray[0] = &sessionData;
    TSS2_SYS_CMD_AUTHS sessionsData = {
        .cmdAuths = &sessionDataArray[0],
        .cmdAuthsCount = 1
    };

    TPM2B_NAME nv_name = { { sizeof(TPM2B_NAME) - 2, } };
    TPM2B_NV_PUBLIC nv_public = { { 0, } };
    TPM_RC rval = Tss2_Sys_NV_ReadPublic(ctx->sapi_ctx,
        strtoul(ctx->nv_index_input, 0, 16), 0, &nv_public, &nv_name,0);
    if (rval != TPM_RC_SUCCESS) {
        printf("\nERROR: Failed NVReadPublic TPM Error: 0x%0x\n\n", rval);
        return FATAL_ERROR;
    }

    uint16_t size = 0;
    uint16_t offset = 0;
    unsigned readcount = (nv_public.t.nvPublic.dataSize/1024) + 1 ;
    unsigned char *nvBuffer = malloc(nv_public.t.nvPublic.dataSize);
    if (nvBuffer == NULL) {
        printf("ERROR: Failed buffer allocation for NV public data\n");
        return FATAL_ERROR;
    }
    unsigned nvbufcnt=0;
    TPM2B_MAX_NV_BUFFER nv_data = { { sizeof(TPM2B_MAX_NV_BUFFER)-2, } };
    int i;
    for(i=0; i< readcount; i++) {
        if(i<readcount) { 
            size = 1024;
        }
        if(i==(readcount-1)) { 
            size = nv_public.t.nvPublic.dataSize % 1024;
            offset = ( (readcount-1)*1024);
        }
        memset(nv_data.t.buffer, 0, (sizeof(TPM2B_MAX_NV_BUFFER)-2));
        rval = Tss2_Sys_NV_Read(  ctx->sapi_ctx, 
                                  TPM_RH_OWNER, 
                                  strtoul(ctx->nv_index_input, 0, 16), 
                                  &sessionsData, 
                                  size, 
                                  offset, 
                                  &nv_data, 
                                  &sessionsDataOut 
                              );
        if(rval != TPM_RC_SUCCESS) {
            printf("\nERROR: Read failure - NV Index 0x%lx\n", 
              strtoul(ctx->nv_index_input, 0, 16));
            free(nvBuffer);
            return -1;
        }
        int j;
        for (j = 0; j < size; j++) {
            nvBuffer[nvbufcnt] = nv_data.t.buffer[j];
            nvbufcnt++;
        }
    }

    if (save_data_to_file(ctx->nv_data_output_file, 
                          nvBuffer, 
                          nv_public.t.nvPublic.dataSize)) {
        printf("\nERROR: Failed to save NV data into file(%s)\n", ctx->EK);
        free(nvBuffer);
        return 1;
    }
    free(nvBuffer);
    return 0;
}

static bool parse_tool_options(int argc, char *argv[], intel_ptt_utility_ctx *ctx) {

   static struct option long_options[] = {
        {"ek-public",       required_argument,  NULL,  'e'},
        {"ek-certificate",  required_argument,  NULL,  'c'},
        {"nv-index",        required_argument,  NULL,  'n'},
        {"make-persistent", no_argument,        NULL,  's'},
        {"check-ptt",       no_argument,        NULL,  'p'},
        {"check-eps",       no_argument,        NULL,  't'},
        {"read-nv-index",   required_argument,  NULL,  'i'},
        {"output-nv-data",  required_argument,  NULL,  'o'},
        {NULL,              no_argument,        NULL, '\0'}
   };

   if (argc == 1) {
       printf("Argument mismatched!\n");
       return false;
   }

   int opt;
   optind=0;
   while ((opt = getopt_long(argc, argv, "e:c:n:i:o:spt", long_options, NULL)) != -1) {
       switch (opt) {
        case 'e':
            ctx->flag_getek = true;
            ctx->EK = strlen(optarg) <= PATH_MAX ? optarg:0;
            break;
        case 'c':
            ctx->flag_getek_cert = true;
            ctx->EK_cert = strlen(optarg) <= PATH_MAX? optarg:0;
            break;
        case 'n':
            ctx->flag_check_nv = true;
            ctx->nv_index_input = strlen(optarg) <= 10? optarg:0;
            break;
        case 'i':
            ctx->flag_read_nv = true;
            ctx->nv_index_input = strlen(optarg) <= 10? optarg:0;
            break;
        case 'o':
            ctx->flag_nv_out = true;
            ctx->nv_data_output_file = strlen(optarg) <= PATH_MAX? optarg:0;
            break;
        case 's':
            ctx->flag_make_persisitent = true;
            break;
        case 'p':
            ctx->flag_is_ptt = true;
            break;
        case 't':
            ctx->flag_is_EPS_from_PTT = true;
            break;
       case ':':
           printf("Argument %c needs a value!\n", optopt);
           return false;
       case '?':
           printf("Unknown Argument: %c\n", optopt);
           return false;
       default:
           printf("?? getopt returned character code 0%o ??\n", opt);
           return false;
       }
   }
   return true;
}

int execute_command(intel_ptt_utility_ctx *ctx) {
    int rval = 0;
    if (ctx->flag_getek) {
        rval = get_current_ek(ctx);
    }
    if (ctx->flag_getek_cert) {
        rval = retrieve_endorsement_key_certificate(ctx,
            base64_encode(hash_EK_public_key(ctx)));
    }
    if (ctx->flag_is_ptt) {
        if (!is_PTT(ctx)) {
            rval = 1;
        }
    }
    if (ctx->flag_is_EPS_from_PTT) {
        if (is_EPS_PTT_generated(ctx)) {
            rval = 1;
        }
    }
    if (ctx->flag_check_nv) {
        rval = check_if_nv_index_defined_and_written(ctx);
    }
    if (ctx->flag_make_persisitent) {
        rval = make_current_ek_persistent(ctx);
    }
    if (ctx->flag_nv_out ^ ctx->flag_read_nv) {
        printf("ERROR: Need NV index AND File path arguments.\n");
        rval = 1;
    }
    if (ctx->flag_nv_out && ctx->flag_read_nv) {
        rval = read_nv_index_to_file(ctx);
    }
    return rval;
}

int main(int argc, char *argv[]) {
    //Intel-PTT-Utility
    intel_ptt_utility_ctx ctx = {
        .flag_getek = false,
        .EK = NULL,
        .flag_getek_cert = false,
        .EK_cert = NULL,
        .flag_is_ptt = false,
        .flag_is_EPS_from_PTT = false,
        .flag_check_nv = false,
        .nv_index_input = NULL,
        .handle_ek = 0,
        .flag_make_persisitent = false
    };

    bool ret = parse_tool_options(argc, argv, &ctx);
    if (!ret) {
        return 1;
    }

    TSS2_TCTI_CONTEXT* tcti_ctx;
    tcti_ctx = tcti_tabrmd_init();
    if (tcti_ctx==NULL) {
        return 1;
    }
    ctx.sapi_ctx = sapi_ctx_init(tcti_ctx);
    if (ctx.sapi_ctx==NULL) {
        return 1;
    }

    int rval = execute_command(&ctx);

    Tss2_Sys_Finalize (ctx.sapi_ctx);
    free (ctx.sapi_ctx);
    tss2_tcti_finalize (tcti_ctx);
    free (tcti_ctx);

    return rval;

}

