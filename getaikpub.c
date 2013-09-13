/*
 * getaikpub.c
 * Try to get the pub key of AIK based on the key handle of AIK - Locally!
 * Build: gcc -o getaikpub getaikpub.c -ltspi
 * Sep 11, 2013
 * root@davejingtian.org
 * http://davejingtian.og
 */

#include <stdio.h>
#include <string.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

#define AIK_HANDLE	0xC0000007
#define NUM_PER_LINE    16
#define TSS_UUID_AIK    {0, 0, 0, 0, 0, {0, 0, 0, 0, 2, 0}}

static char srk_pass[] = "00000000000000000000";

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

	hIdentKey = AIK_HANDLE;

        /* Output the key handler of AIK */
        printf("daveti: AIK_handler=[0x%x]\n", hIdentKey);

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
		return result;
        }

        result = Tspi_Context_GetTpmObject (hContext, &hTPM);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_GetTpmObject failed [%s]\n",
			Trspi_Error_String(result));
		return result;
        }

        result = Tspi_Context_LoadKeyByUUID(hContext,
                        TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_LoadKeyByUUID for SRK failed [%s]\n",
			Trspi_Error_String(result));
		return result;
        }

        result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hSrkPolicy);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_GetPolicyObject for SRK failed [%s]\n",
			Trspi_Error_String(result));
		return result;
        }

        result = Tspi_Policy_SetSecret(hSrkPolicy, TSS_SECRET_MODE_PLAIN, 20, srk_pass);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Policy_SetSecret for SRK failed [%s]\n",
			Trspi_Error_String(result));
		return result;
        }

        result = Tspi_Context_LoadKeyByUUID(hContext,
                        TSS_PS_TYPE_SYSTEM, AIK_UUID, &hIdentKey);
        if (result != TSS_SUCCESS) {
                printf ("Tspi_Context_LoadKeyByUUID for AIK failed [%s]\n",
                        Trspi_Error_String(result));
                return result;
        }

	printf("AIK handle is now [0x%x]\n", hIdentKey);

        result = Tspi_Key_GetPubKey(hIdentKey, &pulPubKeyLength, &prgbPubKey);
        if (result != TSS_SUCCESS)
        {
                printf("Tspi_Key_GetPubKey failed [%s]\n",
                        Trspi_Error_String(result));
		return result;
        }

        /* Output the pub key of AIK */
        display_uchar(prgbPubKey, pulPubKeyLength, "AIK pub key");

	return 0;
}
