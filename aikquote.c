/*
 * aikquote.c
 * Try to get the quote using AIK and verify the signature - Locally!
 * Reference: getaikpub.c, aikquote.c (from privacyca.com)
 * Build: gcc -o aikquote aikquote.c -ltspi
 * Nov 12, 2013
 * Added time measurement for quote and verification
 * Sep 17, 2013
 * Added writting to files for AIK pub key and PCR good value
 * Sep 11, 2013
 * root@davejingtian.org
 * http://davejingtian.og
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

//daveti: timing for key gen
#include <sys/time.h>

#define NUM_PER_LINE    16
#define TSS_UUID_AIK    {0, 0, 0, 0, 0, {0, 0, 0, 0, 2, 0}}
#define PCR_NUM		8
#define PCR_LEN		20
#define PCR_BUF_LEN	(PCR_NUM*PCR_LEN)
#define AIK_PUB_KEY_FILE	"./aik_pub_key.key"
#define PCR_GOOD_VALUE_FILE	"./pcr_good_value.pcr"

/* Define the SRK passwd here used for auth */
static char srk_pass[] = "00000000000000000000";

/* Define the PCR we are interested in */
static unsigned char pcr_quoted[PCR_NUM] =
{
	0,
	1,
	2,
	3,
	4,
	5,
	6,
	7
};
/* Corresponding PCR mask should be binary(11111111) - hex(0xff) */

/* Define the right PCR value for verification */
static unsigned char pcr_good_value[PCR_NUM][PCR_LEN] =
{
	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0},
	{0}
};

static void display_pcrs()
{
	printf("PCRs here:\n");
	int i;
	int j;
	for(i = 0; i < PCR_NUM; i++)
	{
		printf("PCR-%02d: ", pcr_quoted[i]);
		for(j = 0; j < PCR_LEN; j++)
		{
			printf("%02x ", pcr_good_value[i][j]);
		}
		printf("\n");
	}
}

static void display_uchar(unsigned char *src, int len, char *header)
{
	printf("%s\n", header);
        int i;
        for (i = 0; i < len; i++)
        {
                if ((i+1) % NUM_PER_LINE != 0)
                        printf("%02x ", src[i]);
                else
                        printf("%02x\n", src[i]);
        }
        printf("\n");
}

static void display_validation(TSS_VALIDATION *valid)
{
	printf("Validation struct:\n");
	printf("ulExternalDataLength = %u\n", valid->ulExternalDataLength);
	display_uchar(valid->rgbExternalData, valid->ulExternalDataLength, "ExternalData");
	printf("ulDataLength = %u\n", valid->ulDataLength);
	display_uchar(valid->rgbData, valid->ulDataLength, "Data");
	printf("ulValidationDataLength = %u\n", valid->ulValidationDataLength);
	display_uchar(valid->rgbValidationData, valid->ulValidationDataLength, "ValidationData");
}

static void write_pub_key_to_file(unsigned char *key, int len)
{
	FILE *keyfile;
	int ret;

	keyfile = fopen(AIK_PUB_KEY_FILE, "wb");
	if (keyfile == NULL) {
		printf("Unable to create key file [%s]\n", AIK_PUB_KEY_FILE);
		exit(-1);
	}

	ret = fwrite(key, 1, len, keyfile);
	if (ret != len) {
		printf("I/O Error writing key file [%s]\n", AIK_PUB_KEY_FILE);
		exit(-1);
	}

	fclose(keyfile);
	printf("Write key file [%s] done with len [%d]\n",
		AIK_PUB_KEY_FILE, len);
}

static void write_pcr_good_value_to_file()
{
        FILE *pcrfile;
        int ret;
	int len = 0;
	int i;

        pcrfile = fopen(PCR_GOOD_VALUE_FILE, "wb");
        if (pcrfile == NULL) {
                printf("Unable to create PCR file [%s]\n", PCR_GOOD_VALUE_FILE);
                exit(-1);
        }

	for (i = 0; i < PCR_NUM; i++)
	{
        	ret = fwrite(pcr_good_value[i], 1, PCR_LEN, pcrfile);
        	if (ret != PCR_LEN) {
                	printf("I/O Error writing PCR file [%s]\n", AIK_PUB_KEY_FILE);
                	exit(-1);
		}
		len += ret;
        }   

        fclose(pcrfile);
        printf("Write PCR file [%s] done with len [%d]\n",
                AIK_PUB_KEY_FILE, len);
}

static void
sha1(TSS_HCONTEXT hContext, void *buf, UINT32 bufLen, BYTE *digest)
{
        TSS_HHASH       hHash;
        BYTE            *tmpbuf;
        UINT32          tmpbufLen;

        Tspi_Context_CreateObject(hContext,
				TSS_OBJECT_TYPE_HASH,
                		TSS_HASH_SHA1,
				&hHash);
        Tspi_Hash_UpdateHashValue(hHash, bufLen, (BYTE *)buf);
        Tspi_Hash_GetHashValue(hHash, &tmpbufLen, &tmpbuf);
        memcpy(digest, tmpbuf, tmpbufLen);
        Tspi_Context_FreeMemory(hContext, tmpbuf);
        Tspi_Context_CloseObject(hContext, hHash);
}


int main(void)
{
        TSS_HCONTEXT    hContext;
        TSS_HTPM        hTPM;
        TSS_HKEY        hSRK;
	TSS_RESULT 	result;
        TSS_HKEY        hIdentKey;
	TSS_UUID        SRK_UUID = TSS_UUID_SRK;
	TSS_UUID        AIK_UUID = TSS_UUID_AIK;
        TSS_HPOLICY     hSrkPolicy;
        UINT32          pulPubKeyLength;
        BYTE            *prgbPubKey;
	TSS_HPCRS	hPcrComposite;
	TSS_VALIDATION	pValidationData;
	UINT32 		ulRandomDataLength;
	BYTE 		*prgbRandomData;
	UINT32		ulPcrLen;
	BYTE		*rgbPcrValue;
	BYTE		nonce[TPM_SHA1BASED_NONCE_LEN];
	BYTE		digest[TPM_SHA1BASED_NONCE_LEN];
        TSS_HHASH	hHash;
        TSS_HKEY	hKey;
        UINT32		ulSignatureLength;
        BYTE		*rgbSignature;
	TPM_QUOTE_INFO	*quote;
        UINT32          tpmProp;
        UINT32          npcrMax;
        UINT32          npcrBytes;
        BYTE            *buf = NULL;
        UINT32          bufLen;
        BYTE            *bp;
        BYTE            *tmpbuf;
        UINT32          tmpbufLen;
        UINT32          initFlags = TSS_KEY_TYPE_SIGNING
					| TSS_KEY_SIZE_2048
					| TSS_KEY_NO_AUTHORIZATION
                                        | TSS_KEY_NOT_MIGRATABLE;
	int		i;
	int		rtn = 0;

	/* Trousers preamble */
        result = Tspi_Context_Create(&hContext);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_Create failed [%s]\n",
			Trspi_Error_String(result));
                return result;
        }

        result = Tspi_Context_Connect(hContext, NULL);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_Connect failed [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
        }

        result = Tspi_Context_GetTpmObject (hContext, &hTPM);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_GetTpmObject failed [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
        }

        result = Tspi_Context_LoadKeyByUUID(hContext,
                        TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_LoadKeyByUUID for SRK failed [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
        }

        result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_GetPolicyObject for SRK failed [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
        }

        result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN, 20, srk_pass);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Policy_SetSecret for SRK failed [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
        }

        result = Tspi_Context_LoadKeyByUUID(hContext,
                        TSS_PS_TYPE_SYSTEM, AIK_UUID, &hIdentKey);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_LoadKeyByUUID for AIK failed [%s]\n",
                        Trspi_Error_String(result));
		rtn = -1;
		goto close;
        }

	printf("AIK handle is now [0x%x]\n", hIdentKey);

	/* Get the pub key of AIK for futher quote verification */
        result = Tspi_Key_GetPubKey(hIdentKey, &pulPubKeyLength, &prgbPubKey);
        if (result != TSS_SUCCESS)
        {
                printf("Tspi_Key_GetPubKey failed [%s]\n",
                        Trspi_Error_String(result));
		rtn = -1;
		goto close;
        }

        /* Output the pub key of AIK */
        display_uchar(prgbPubKey, pulPubKeyLength, "AIK pub key");

	/* Write the pub key into the file */
	write_pub_key_to_file(prgbPubKey, pulPubKeyLength);

	/* Get the nonce locally for further quote */
	ulRandomDataLength = TPM_SHA1BASED_NONCE_LEN; /* 20 bytes */

//daveti: add time measurement for rand
struct timeval tpstart1,tpend1;
float timeuse1 = 0;
gettimeofday(&tpstart1,NULL);

	result = Tspi_TPM_GetRandom(hTPM,
				ulRandomDataLength,
				&prgbRandomData);

//daveti: end time for rand
gettimeofday(&tpend1,NULL);
timeuse1=1000000*(tpend1.tv_sec-tpstart1.tv_sec)+tpend1.tv_usec-tpstart1.tv_usec;
timeuse1/=1000000;
printf("Total time on Tspi_TPM_GetRandom() is [%f] ms\n", timeuse1);

	if (result != TSS_SUCCESS)
	{
		printf("Tspi_TPM_GetRandom failed [%s]\n", Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

	/* Copy the nonce into nonce */
	memcpy(nonce, prgbRandomData, TPM_SHA1BASED_NONCE_LEN);
	display_uchar(nonce, TPM_SHA1BASED_NONCE_LEN, "Local nonce in nonce");

#ifdef UT1
rtn = 0;
goto close;
#endif

	/* Prepare the buf for the future digest verification */
        tpmProp = TSS_TPMCAP_PROP_PCR;
        result = Tspi_TPM_GetCapability(hTPM,
				TSS_TPMCAP_PROPERTY,
				sizeof(tpmProp),
				(BYTE *)&tpmProp,
				&tmpbufLen,
				&tmpbuf);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_TPM_GetCapability failed [%s]\n", Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}
        npcrMax = *(UINT32 *)tmpbuf;
        Tspi_Context_FreeMemory(hContext, tmpbuf);
        npcrBytes = (npcrMax + 7) / 8;
	/* Debug */
	printf("npcrMax = [%u], npcrBytes = [%u]\n", npcrMax, npcrBytes);

	/* Allocate and init the buf */
        buf = malloc (2 + npcrBytes + 4 + PCR_LEN * npcrMax);
        *(UINT16 *)buf = htons(npcrBytes);
        for (i = 0; i < npcrBytes; i++)
                buf[2+i] = 0;

	/* Get the right PCR value for future reference */
	for(i = 0; i < PCR_NUM; i++)
	{
		result = Tspi_TPM_PcrRead(hTPM, pcr_quoted[i], &ulPcrLen, &rgbPcrValue);
		if (result != TSS_SUCCESS)
		{
			printf("Tspi_TPM_PcrRead failed for PCR [%u] [%s]\n",
				pcr_quoted[i], Trspi_Error_String(result));
			rtn = -1;
			goto close;
		}
		display_uchar(rgbPcrValue, ulPcrLen, "Got PCR value");

		/* Copy the value into static mem */
		if (ulPcrLen != PCR_LEN)
		{
			printf("daveti: Is this possible?\n");
			rtn = -1;
			goto close;
		}
		memcpy(pcr_good_value[i], rgbPcrValue, PCR_LEN);

		/* Magic operation for pcr buf...*/
		buf[2+(pcr_quoted[i]/8)] |= 1 << (pcr_quoted[i]%8);
	}

	/* Output the PCRs */
	display_pcrs();

	/* Write the PCRs into file */
	write_pcr_good_value_to_file();

	/* Fill in rest of PCR buffer */
        bp = buf + 2 + npcrBytes;
        *(UINT32 *)bp = htonl(PCR_LEN*PCR_NUM);
        bp += sizeof(UINT32);
        for(i = 0; i < PCR_NUM; i++)
        {
		memcpy(bp, pcr_good_value[i], PCR_LEN);
		bp += PCR_LEN;
        }
        bufLen = bp - buf;

	/* Output the pcrBuf */
	printf("pcrBufLen = [%u]\n", bufLen);
	display_uchar(buf, bufLen, "pcrBuf");

#ifdef UT2
rtn = 0;
goto close;
#endif

//daveti: add time measurement for quote
struct timeval tpstart,tpend;
float timeuse = 0;
gettimeofday(&tpstart,NULL);

	/* Create the PCR Composite object for quote */
	result = Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_PCRS,
					0,
					&hPcrComposite);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Context_CreateObject failed for PCR Composite [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

	/* Set the quoted PCR index */
	for (i = 0; i < PCR_NUM; i++)
	{
		result = Tspi_PcrComposite_SelectPcrIndex(hPcrComposite, pcr_quoted[i]);
		if (result != TSS_SUCCESS)
		{
			printf("Tspi_PcrComposite_SelectPcrIndex failed for index [%d] [%s]\n",
				pcr_quoted[i], Trspi_Error_String(result));
			rtn = -1;
			goto close;
		}
	}

	/* Set the input for validation struct */
        pValidationData.ulExternalDataLength = TPM_SHA1BASED_NONCE_LEN;
        pValidationData.rgbExternalData = nonce;

	/* Do the damn quote */
	result = Tspi_TPM_Quote(hTPM,                           /* in */
				hIdentKey,                      /* in */
				hPcrComposite,                 /* in */
				&pValidationData);        /* in, out */
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_TPM_Quote failed [%s]\n", Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

//daveti: end of measure for quote
gettimeofday(&tpend,NULL);
timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
timeuse/=1000000;
printf("Total time on Tspi_TPM_Quote() is [%f] ms\n", timeuse);

	/* Debug */
	display_validation(&pValidationData);

	/* Get the digest of PCRs value */
	quote = (TPM_QUOTE_INFO *)pValidationData.rgbData;
	display_uchar(quote->compositeHash.digest, TPM_SHA1_160_HASH_LEN, "PCRs value digest");

#ifdef UT3
rtn = 0;
goto close;
#endif

//daveti: add time measurement for verify
struct timeval tpstart2,tpend2;
float timeuse2 = 0;
gettimeofday(&tpstart2,NULL);

	/* Verify the PCRs value digest locally */
	sha1(hContext, buf, bufLen, digest);
	display_uchar(digest, TPM_SHA1_160_HASH_LEN, "SHA1 PCR digest");
	if (memcmp(quote->compositeHash.digest, digest, TPM_SHA1_160_HASH_LEN) != 0)
	{
                /* Try with smaller digest length */
		printf("Try with smaller digest length\n");
                *(UINT16 *)buf = htons(npcrBytes-1);
                memmove(buf+2+npcrBytes-1, buf+2+npcrBytes, bufLen-2-npcrBytes);
                bufLen -= 1;
		/* Output the pcrBuf */
		printf("pcrBufLen(smaller) = [%u]\n", bufLen);
		display_uchar(buf, bufLen, "pcrBuf(smaller)");
                sha1(hContext, buf, bufLen, digest);
		display_uchar(digest, TPM_SHA1_160_HASH_LEN, "SHA1 PCR digest(smaller)");
		if (memcmp(quote->compositeHash.digest, digest, TPM_SHA1_160_HASH_LEN) != 0)
		{
			printf("digest verification failed\n");
			rtn = -1;
			goto close;
		}
	}
	printf("PCRs Value Digest Verification Success\n");

#ifdef UT4
rtn = 0;
goto close;
#endif

	/* Assume here:
	 * validation.rgbValidationData = SHA1(validation.rgbData)
	 */

	/* Create the hash data used for signature verification */
        result = Tspi_Context_CreateObject(hContext,
                                	TSS_OBJECT_TYPE_HASH,
                                	TSS_HASH_SHA1,
                                	&hHash);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Context_CreateObject failed for hash data [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

	/* Set the hash data the same as validation rgbData */
        result = Tspi_Hash_UpdateHashValue(hHash,
					pValidationData.ulDataLength,
					(BYTE *)pValidationData.rgbData);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Hash_UpdateHashValue failed for hash data [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

	/* Create verification key */
	result = Tspi_Context_CreateObject(hContext,
					TSS_OBJECT_TYPE_RSAKEY,
					initFlags,
					&hKey);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Context_CreateObject failed hKey [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

	/* Load the AIK pub key into the verification key */
	result = Tspi_SetAttribData(hKey,
				TSS_TSPATTRIB_KEY_BLOB,
				TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
				pulPubKeyLength,
				prgbPubKey);
	if (result != TSS_SUCCESS)
	{
		printf("Tspi_SetAttribData failed [%s]\n",
			Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}

	/* Set the input for the signature verfification */
	ulSignatureLength = pValidationData.ulValidationDataLength;
	rgbSignature = pValidationData.rgbValidationData;

//daveti: add time measurement for verifySig
struct timeval tpstart3,tpend3;
float timeuse3 = 0;
gettimeofday(&tpstart3,NULL);

	/* Verify the damn quote using AIK pub key */
	result = Tspi_Hash_VerifySignature(hHash,              /* in */
                          		hKey,                /* in */
                          		ulSignatureLength,     /* in */
                          		rgbSignature);          /* in */

//daveti: end of measure for verifySig
gettimeofday(&tpend3,NULL);
timeuse3=1000000*(tpend3.tv_sec-tpstart3.tv_sec)+tpend3.tv_usec-tpstart3.tv_usec;
timeuse3/=1000000;
printf("Total time on Tspi_Hash_VerifySignature() is [%f] ms\n", timeuse3);

//daveti: end of measure for verify 
gettimeofday(&tpend2,NULL);
timeuse2=1000000*(tpend2.tv_sec-tpstart2.tv_sec)+tpend2.tv_usec-tpstart2.tv_usec;
timeuse2/=1000000;
printf("Total time on TPM_Verify() is [%f] ms\n", timeuse2);

	if (result != TSS_SUCCESS)
	{
		printf("Tspi_Hash_VerifySignature failed [%s]\n", Trspi_Error_String(result));
		rtn = -1;
		goto close;
	}
	printf("Signature Verification Success\n");

close:
	if (buf != NULL)
		free(buf);
	Tspi_Context_Close(hContext);
	return rtn;
}
