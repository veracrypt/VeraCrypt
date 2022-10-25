#include "IccExtractor.h"

/* Cleaning function in case of error*/
int ErrorClean(){

    /* Release memory that has been returned from the resource manager using the SCARD_AUTOALLOCATE length
     * designator*/
    if (mszReaders) {
        SCardFreeMemory(hContext, mszReaders);
    }

    /* Closing the established resource manager context freeing any resources allocated under that context
     * including SCARDHANDLE objects and memory allocated using the SCARD_AUTOALLOCATE length designator*/
    returnValue = SCardReleaseContext(hContext);
    if (returnValue != SCARD_S_SUCCESS) {
        printf("SCardReleaseContext: %ld (0x%lX)\n", hContext, returnValue);
    }

    /*Release memory allocated to the card readers pointers*/
    if (readers) {
        free(readers);
    }
    exit(EXIT_SUCCESS);
}

/* Printing PCSC error message*/
void PCSC_ERROR(LONG rv, char* text){
    if (rv != SCARD_S_SUCCESS)
    {
        printf("%s: %lu (0x%lX)\n",text, (rv), rv); \
        ErrorClean();
    }
    else
    {
        printf("%s: OK\n",text);
    }
}

/* Establishing the resource manager context (the scope) within which database operations are performed.
 * The module of the smart card subsystem that manages access to multiple readers and smart cards. The
 * resource manager identifies and tracks resources, allocates readers and resources across multiple
 * applications,and supports transaction primitives for accessing services available on a given card.*/
int EstablishRSContext(){
    printf("Establishing resource manager context ...\n");
    returnValue = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
    if (returnValue != SCARD_S_SUCCESS)
    {
        printf("SCardEstablishContext: Cannot Connect to Resource Manager %lX\n", returnValue);
        return EXIT_FAILURE;
    }
}

/* Detecting available readers and filling the reader table */
int GetReaders(){
    printf("Getting available readers...\n");
    /* Retrieving the available readers list and putting it in mszReaders*/
    dwReaders = SCARD_AUTOALLOCATE;
    returnValue = SCardListReaders(hContext, NULL, (LPSTR)&mszReaders, &dwReaders);
    PCSC_ERROR(returnValue, "SCardListReaders");


    char *ptr=NULL;
    int nbReaders = 0;
    ptr = mszReaders;

    /* Getting the total number of readers */
    while (*ptr != '\0')
    {
        ptr += strlen(ptr) + 1;
        nbReaders++;
    }

    if (nbReaders == 0)
    {
        printf("No reader found\n");
        ErrorClean();
    }

    /* Allocating the readers table with to contain nbReaders readers*/
    readers = (char**) calloc(nbReaders, sizeof(char *));
    if (NULL == readers)
    {
        printf("Not enough memory to allocate the reader table\n");
        ErrorClean();
    }

    /* Filling the readers table */
    nbReaders = 0;
    ptr = mszReaders;
    while (*ptr != '\0')
    {
        printf("%d: %s\n", nbReaders, ptr);
        readers[nbReaders] = ptr;
        ptr += strlen(ptr) + 1;
        nbReaders++;
    }
    return EXIT_SUCCESS;
}

/* Selecting the reader number (index in the table)*/
int SelectReaderNumber(int argc, char * readerNumber) {
    int reader_nb;
    if (argc > 1) {
        reader_nb = atoi(readerNumber);
        if (reader_nb < 0 || reader_nb >= nbReaders) {
            printf("Wrong reader index: %d\n", reader_nb);
            ErrorClean();
        }
    }else{
        reader_nb = 0;
    }
    return reader_nb;
}

/* Connecting to the card*/
int ConnectCard(int reader_nb){
    printf("Connecting to card...\n");
    dwActiveProtocol = -1;
    returnValue = SCardConnect(hContext, readers[reader_nb], SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
    printf(" Protocol: %ld\n", dwActiveProtocol);
    PCSC_ERROR(returnValue, "SCardConnect");

    return EXIT_SUCCESS;
}

/* Getting the status of the card connected */
int StatusCard(){
    printf("Getting card status...\n");
    dwAtrLen = sizeof(pbAtr);
    dwReaderLen = sizeof(pbReader);
    returnValue=SCardStatus(hCard, /*NULL*/ pbReader, &dwReaderLen, &dwState, &dwProt,
                            pbAtr, &dwAtrLen);

    printf(" Reader: %s (length %ld bytes)\n", pbReader, dwReaderLen);
    printf(" State: 0x%lX\n", dwState);
    printf(" Protocol: %ld\n", dwProt);
    printf(" ATR (length %ld bytes):", dwAtrLen);
    for (int i = 0; i < dwAtrLen; i++) {
        printf(" %02X", pbAtr[i]);
    }
    printf("\n");
    PCSC_ERROR(returnValue, "SCardStatus");

    switch (dwActiveProtocol)
    {
        case SCARD_PROTOCOL_T0:
            pioSendPci.dwProtocol = SCARD_PROTOCOL_T0;
            pioSendPci.cbPciLength = sizeof(pioRecvPci);
            printf("T0 \n");
            break;
        case SCARD_PROTOCOL_T1:
            pioSendPci.dwProtocol = SCARD_PROTOCOL_T1;
            pioSendPci.cbPciLength = sizeof(pioRecvPci);
            printf("T1 \n");
            break;
        default:
            printf("Unknown protocol\n");
            ErrorClean();
    }

    return EXIT_SUCCESS;
}

/* Testing if the card contains the application of the given EMV type */
int TestingCardType(BYTE * SELECT_TYPE){

    /* exchange APDU  : TYPE */
    dwSendLength = SELECT_TYPE_SIZE;
    dwRecvLength = sizeof(pbRecvBuffer);


    returnValue = SCardTransmit(hCard, &pioSendPci, SELECT_TYPE, dwSendLength, NULL, pbRecvBuffer, &dwRecvLength);

    PCSC_ERROR(returnValue, "SCardTransmit");
    printf("Error : %lx \n", returnValue);

    printf("Receiving: ");
    for (int i = 0; i < dwRecvLength; i++) {
        printf("%02X ", pbRecvBuffer[i]);
    }
    printf("\n");
    if (pbRecvBuffer[0] == 0x61)return 1;

    return 0;
}

/* Getting the ICC Public Key Certificates and the Issuer Public Key Certificates by parsing the application */
int GetCerts(unsigned char* ICC_CERT, unsigned char* ISSUER_CERT){
    printf("Getting public key certificates ... \n");
    int iccFound=0;
    int issuerFound=0;
    /* Parsing root folders */
    for (int sfi = 0; sfi < 32; sfi++)
    {
        /* Parsing sub folders */
        for (int rec = 0; rec < 17; rec++)
        {
            BYTE SELECT_APDU_FILE[] = {00, 0xB2, rec, (sfi << 3) | 4, 0x00};
            /* Exchange APDU  : SELECT FILE */
            dwSendLength = sizeof(SELECT_APDU_FILE);
            dwRecvLength = sizeof(pbRecvBuffer);
            returnValue = SCardTransmit(hCard, &pioSendPci, SELECT_APDU_FILE, dwSendLength,
                                        NULL, pbRecvBuffer, &dwRecvLength);

            /* No record */
            if (pbRecvBuffer[0] == 0x6A){
                continue;
            }
            else if (pbRecvBuffer[0] == 0x6C){
                SELECT_APDU_FILE[4] = pbRecvBuffer[1];

                dwRecvLength = sizeof(pbRecvBufferFat);

                returnValue = SCardTransmit(hCard, &pioSendPci, SELECT_APDU_FILE, dwSendLength,
                                            NULL, pbRecvBufferFat, &dwRecvLength);
                
                struct TLVNode* node = TLV_Parse(pbRecvBufferFat,sizeof(pbRecvBufferFat));
                /* Finding the ICC_Public_Key_Certificate */
                struct TLVNode* ICC_Public_Key_Certificate = TLV_Find(node, 0x9F46);
                if(ICC_Public_Key_Certificate) {
                    iccFound=1;
                    ICC_CERT = ICC_Public_Key_Certificate->Value;
                }

                /* Finding the ICC_Public_Key_Certificate */
                struct TLVNode* Issuer_PK_Certificate = TLV_Find(node, 0x90);
                if(Issuer_PK_Certificate) {
                    issuerFound=1;
                    ISSUER_CERT = Issuer_PK_Certificate->Value;
                }

                /* Limiting the search of one occurrence of both PKs per application to speed up the process.
                 * There might be more certificates tho*/
                if(iccFound && issuerFound)return 0;
            }
        }
    }
    printf("One of the Public keys is missing in this application\n");
    return 1;
}

/* Getting CPCL data from the card*/
int GetCPCL(unsigned char* CPCL){
    printf("Getting CPCL data ... \n");

    BYTE SELECT_APDU_CPCL[] = {0x80,0xCA, 0x9F, 0x7F, 0x00};

    dwSendLength = sizeof(SELECT_APDU_CPCL);
    dwRecvLength = sizeof(pbRecvBuffer);
    returnValue = SCardTransmit(hCard, &pioSendPci, SELECT_APDU_CPCL, dwSendLength,
                                NULL, pbRecvBuffer, &dwRecvLength);

    /* No record */
    if (pbRecvBuffer[0] == 0x6A)
    {
        printf("No CPCL data on the card");
    }else if (pbRecvBuffer[0] == 0x6C){
        SELECT_APDU_CPCL[4] = pbRecvBuffer[1];
        dwRecvLength = sizeof(pbRecvBufferFat);

        returnValue = SCardTransmit(hCard, &pioSendPci, SELECT_APDU_CPCL, dwSendLength,
                                    NULL, pbRecvBufferFat, &dwRecvLength);

        CPCL = pbRecvBufferFat;
        return 0;
    } else{
        printf("Unexpected bahavior");
        return 1;
    }
}

/* Getting an ICC Public Key Certificates and an Issuer Public Key Certificates for the first application with the cpcl data present on the card and finally merge it into one byte array */
int GettingAllCerts(unsigned char* data){
    int isEMV=0;
    int hasCPCL=0;
    int hasCerts=0;
    unsigned char* CPCL;
    if(GetCPCL(CPCL)==0){
        memcpy(data, CPCL, sizeof(CPCL));
        hasCPCL=1;
    }
    for(int i=0;i<sizeof(SELECT_TYPES)/sizeof(SELECT_TYPES[0]); i++){
        if(TestingCardType(SELECT_TYPES[i])){
            isEMV=1;
            unsigned char* ICC_CERT;
            unsigned char* ISSUER_CERT;
            if(GetCerts(ICC_CERT, ISSUER_CERT)==0){
                memcpy(data+sizeof(CPCL),ICC_CERT, sizeof(ICC_CERT));
                memcpy(data+sizeof(CPCL)+sizeof(ICC_CERT),ISSUER_CERT, sizeof(ISSUER_CERT));
                hasCerts=1;
                break;
            }
        } else{

        }
    }
    if(isEMV==0){
        printf("Unknown card type\n");
        ErrorClean();
        return 1;
    }
    if (hasCPCL==0 || hasCerts==0){
        printf("No CPCL data or Certs on the card\n");
        ErrorClean();
        return 1;
    }
    return 0;
    
}

/* Cleaning function to end properly the protocol*/
int FinishClean(){
    printf("Finishing Cleaning ... \n");
    /* Ending transaction */
    fprintf(stderr,"-> End transaction...");
    returnValue = SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
    fprintf(stderr," Done with return value %s \n",returnValue);
    //PCSC_ERROR(returnValue, "SCardEndTransaction"); //TODO: Fix this error by permitting PCSC_ERROR() to print (maybe in stderr)


    /* Disconnecting the card */
    fprintf(stderr,"-> Disconnecting the card...");
    returnValue = SCardDisconnect(hCard, SCARD_UNPOWER_CARD);
    printf(stderr," Done with return value %s \n",returnValue);
    //PCSC_ERROR(returnValue, "SCardDisconnect"); //TODO: Fix this error by permitting PCSC_ERROR() to print (maybe in stderr)

    return EXIT_SUCCESS;
}
