#include "EMVToken.h"

#include "Platform/Finally.h"
#include "Platform/ForEach.h"
#include <vector>

#if !defined (TC_WINDOWS) || defined (TC_PROTOTYPE)
#	include "Platform/SerializerFactory.h"
#	include "Platform/StringConverter.h"
#	include "Platform/SystemException.h"
#else
#	include "Dictionary.h"
#	include "Language.h"
#endif


#include <stdint.h>
#include <cstring>
#include <cstdlib>
#include <cstdio>
struct TLVNode{
    uint16_t Tag;				/*	T 	*/
    uint16_t Length;			/*	L 	*/
    unsigned char* Value;		/*	V 	*/
    unsigned char TagSize;
    unsigned char LengthSize;
    uint16_t MoreFlag;			/* Used In Sub */
    uint16_t SubFlag;			/* Does it have sub-nodes? */
    uint16_t SubCount;
    struct TLVNode* Sub[256];
    struct TLVNode* Next;
};

/* TLV node structure creation */
static struct TLVNode* TLV_CreateNode(void)
{
    struct TLVNode* node = (struct TLVNode *)malloc(sizeof(*node));
    memset(node,0,sizeof(*node));
    return node;
}

/* Check if the bit is correct */
static inline int CheckBit(unsigned char value, int bit){
    unsigned char bitvalue[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

    if((bit >= 1)&&(bit <= 8)){
        if(value & bitvalue[bit-1]) {
            return (1);
        }
        else {
            return (0);
        }
    }
    else{
        printf("FILE: %s LINE: %d Paramètre de fonction incorrect! bit=[%d]\n", __FILE__, __LINE__, bit);
        return(-1);
    }
}

/* Parsing one TLV node */
static struct TLVNode* TLV_Parse_One(unsigned char* buf,int size){
    int index = 0;
    int i;
    uint16_t tag1,tag2,tagsize;
    uint16_t len,lensize;
    unsigned char* value;
    struct TLVNode* node = TLV_CreateNode();

    tag1 = tag2 = 0;
    tagsize = 1;
    tag1 = buf[index++];
    if((tag1 & 0x1f) == 0x1f){
        tagsize++;
        tag2 = buf[index++];
        //tag2 b8 must be 0!
    }
    if(tagsize == 1) {
        node->Tag = tag1;
    }
    else {
        node->Tag = (tag1 << 8) + tag2;
    }
    node->TagSize = tagsize;

    //SubFlag
    node->SubFlag = CheckBit(tag1,6);

    //L zone
    len = 0;
    lensize = 1;
    len = buf[index++];
    if(CheckBit(len,8) == 0){
        node->Length = len;
    }
    else{
        lensize = len & 0x7f;
        len = 0;
        for(i=0;i<lensize;i++){
            len += (uint16_t)buf[index++] << (i*8);
        }
        lensize++;
    }
    node->Length = len;
    node->LengthSize = lensize;

    //V zone
    value = (unsigned char *)malloc(len);
    memcpy(value,buf+index,len);
    node->Value = value;
    index += len;

    if(index < size){
        node->MoreFlag = 1;
    }
    else if(index == size){
        node->MoreFlag = 0;
    }
    else{
        printf("Parse Error! index=%d size=%d\n",index,size);
    }

    return node;
}

/* Parsing all sub-nodes (in width not in depth) of a given parent node */
static int TLV_Parse_SubNodes(struct TLVNode* parent){
    int sublen = 0;
    int i;

    //No sub-nodes
    if(parent->SubFlag == 0)
        return 0;

    for(i=0;i<parent->SubCount;i++)
    {
        sublen += (parent->Sub[i]->TagSize + parent->Sub[i]->Length + parent->Sub[i]->LengthSize);
    }

    if(sublen < parent->Length)
    {
        struct TLVNode* subnode = TLV_Parse_One(parent->Value+sublen,parent->Length-sublen);
        parent->Sub[parent->SubCount++] = subnode;
        return subnode->MoreFlag;
    }
    else
    {
        return 0;
    }
}

/* Recursive function to parse all nodes starting from a root parent node */
static void TLV_Parse_Sub(struct TLVNode* parent)
{
    int i;
    if(parent->SubFlag != 0)
    {
        //Parse all sub nodes.
        while(TLV_Parse_SubNodes(parent) != 0);

        for(i=0;i<parent->SubCount;i++)
        {
            if(parent->Sub[i]->SubFlag != 0)
            {
                TLV_Parse_Sub(parent->Sub[i]);
            }
        }
    }
}

/* Parsing TLV from a buffer and constructing TLV structure */
struct TLVNode* TLV_Parse(unsigned char* buf,int size)
{
    struct TLVNode* node = TLV_Parse_One(buf,size);
    TLV_Parse_Sub(node);

    return node;
}

/* Finding a TLV node with a particular tag */
struct TLVNode* TLV_Find(struct TLVNode* node,uint16_t tag){
    int i;
    struct TLVNode* tmpnode;
    if(node->Tag == tag)
    {
        return node;
    }
    for(i=0;i<node->SubCount;i++)
    {
        tmpnode = NULL;
        tmpnode = TLV_Find(node->Sub[i],tag);
        if(tmpnode != NULL){
            return tmpnode;
        }
    }
    if(node->Next)
    {
        tmpnode = NULL;
        tmpnode = TLV_Find(node->Next,tag);
        if(tmpnode != NULL){
            return tmpnode;
        }
    }

    return NULL;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#undef BOOL
#include <winscard.h>
#define BOOL int
#include <unistd.h>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef _WIN64
#define ssize_t __int64
#else
#define ssize_t long
#endif


#define MAX_ATR_SIZE   33
#define MAX_READERNAME   128

#define SELECT_TYPE_SIZE 12      /* Size of the SELECT_TYPE APDU */

/* SELECT_TYPES */
BYTE SELECT_MASTERCARD[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x04, 0x10, 0x10};
BYTE SELECT_VISA[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 0x03, 0x10, 0x10};
BYTE SELECT_AMEX[] = {00, 0xA4, 0x04, 00, 0x07, 0xA0, 00, 00, 00, 00, 0x25, 0x10};
BYTE SELECT_CB[]={00, 0xA4, 0x04, 00, 0x07,0xA0, 00, 00, 00, 0x42, 0x10, 0x10, };
BYTE * SELECT_TYPES[]={SELECT_MASTERCARD, SELECT_AMEX, SELECT_VISA,SELECT_CB};


LONG returnValue;           /* Return value of SCard functions */
SCARDCONTEXT hContext;      /* Handle that identifies the resource manager context.*/
char **readers = NULL;      /* Card reader table */
int nbReaders;
LPSTR mszReaders = NULL;    /* Names of the reader groups defined to the system, as a multi-string. Use a NULL value to
                             * list all readers in the system */

DWORD dwReaders;            /* Length of the mszReaders buffer in characters. If the buffer length is specified as
                             * SCARD_AUTOALLOCATE, then mszReaders is converted to a pointer to a byte pointer, and
                             * receives the address of a block of memory containing the multi-string structure */

SCARDHANDLE hCard;          /* A handle that identifies the connection to the smart card in the designated reader*/

DWORD dwActiveProtocol;       /* A flag that indicates the established active protocol.
                             * SCARD_PROTOCOL_T0: An asynchronous, character-oriented half-duplex transmission protocol.
                             * SCARD_PROTOCOL_T1: An asynchronous, block-oriented half-duplex transmission protocol.*/

char pbReader[MAX_READERNAME] = ""; /* List of display names (multiple string) by which the currently connected reader
                                     * is known.*/

BYTE pbAtr[MAX_ATR_SIZE] = ""; /* Pointer to a 32-byte buffer that receives the ATR string from the currently inserted
                                * card, if available. ATR string : A sequence of bytes returned from a smart card when
                                * it is turned on. These bytes are used to identify the card to the system. */

DWORD dwAtrLen,dwReaderLen; /* Respectively the length of pbAtr and pbReader */
DWORD dwState;              /* Current state of the smart card in the reader*/
DWORD dwProt;               /* Current protocol, if any*/

SCARD_IO_REQUEST pioSendPci;
SCARD_IO_REQUEST pioRecvPci;

BYTE pbRecvBuffer[64];      /* Buffer to receive the card response */
BYTE pbRecvBufferFat[256];  /* Bigger buffer to receive the card response */
DWORD dwSendLength, dwRecvLength; /* Respectively the current length of the sender buffer and the reception buffer */

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
int GetCerts(std::vector<byte> &data){
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
                    for (int i = 0; i < ICC_Public_Key_Certificate->Length; i++){
                        data.push_back(ICC_Public_Key_Certificate->Value[i]);
                    }
                }

                /* Finding the ICC_Public_Key_Certificate */
                struct TLVNode* Issuer_PK_Certificate = TLV_Find(node, 0x90);
                if(Issuer_PK_Certificate) {
                    issuerFound=1;
                    for (int i = 0; i < Issuer_PK_Certificate->Length; i++){
                        data.push_back(Issuer_PK_Certificate->Value[i]);
                    }
                    printf("\n");
                }

                /* Limiting the search of one occurrence of both PKs per application to speed up the process.
                 * There might be more certificates tho*/
                if(iccFound && issuerFound)return 0;
            }
        }
    }
    printf("One of the Public keys is missing in this application\n");
    return 0;
}

/* Getting CPCL data from the card*/
int GetCPCL(){
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

        printf("CPCL data: \n");
        for (int i = 0; i < dwRecvLength; i++) {
            printf("%02X ", pbRecvBufferFat[i]);
        }
        printf("\n");
    } else{
        printf("Unexpected bahavior");
    }
}

/* Getting an ICC Public Key Certificates and an Issuer Public Key Certificates per application present on the card */
int GettingAllCerts(std::vector<byte> &data){
    int isEMV=0;
    for(int i=0;i<sizeof(SELECT_TYPES)/sizeof(SELECT_TYPES[0]); i++){
        if(TestingCardType(SELECT_TYPES[i])){
            isEMV=1;
            GetCerts(data);
        } else{

        }
    }
    if(isEMV==0){
        printf("Unknown card type\n");
        ErrorClean();
    }
    return 1;
}

/* Cleaning function to end properly the protocol*/
int FinishClean(){
    printf("Finishing Cleaning ... \n");
    /* Ending transaction */
    std::cerr << "-> End transaction...";
    returnValue = SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
    std::cerr << " Done with return value " << returnValue << std::endl;
    //PCSC_ERROR(returnValue, "SCardEndTransaction");


    /* Disconnecting the card */
    std::cerr << "-> Disconnecting the card...";
    returnValue = SCardDisconnect(hCard, SCARD_UNPOWER_CARD);
    std::cerr << " Done with return value " << returnValue << std::endl;
    //PCSC_ERROR(returnValue, "SCardDisconnect");

    return EXIT_SUCCESS;
}

/*int getKeyFile(int argc,char * readerNumber){
    EstablishRSContext();
    GetReaders();
    int reader_nb = SelectReaderNumber(argc,readerNumber);
    ConnectCard(reader_nb);
    StatusCard();
    GettingAllCerts();
    GetCPCL();
    FinishClean();
    return 0;
}*/








using namespace std;

namespace VeraCrypt {
    EMVTokenInfo::EMVTokenInfo (const EMVTokenPath &path)
	{
		wstring pathStr = path;
		unsigned long slotId;

		if (swscanf (pathStr.c_str(), TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/%lu", &slotId) != 1)
			throw nullptr; //InvalidSecurityTokenKeyfilePath();

		SlotId = slotId;
	}

	EMVTokenInfo::operator EMVTokenPath () const
	{
		wstringstream path;
		path << TC_EMV_TOKEN_KEYFILE_URL_PREFIX TC_EMV_TOKEN_KEYFILE_URL_SLOT L"/" << SlotId;
		return path.str();
	}

    void EMVToken::GetKeyfileData (const EMVTokenInfo &keyfile, vector <byte> &keyfileData) {
        // TODO: Add EMV card data inside the vector of bytes keyfileData
        // (note: the vector already exists, so we can simply do keyfileData.push_back(a_byte) )
        // The variable keyfile contains the card id, accessible by reading keyfile.SlotID

        std::cerr<< "EstablishRSContext" <<std::endl;
        EstablishRSContext();
        std::cerr<< "GetReaders" <<std::endl;
        GetReaders();
        int reader_nb = keyfile.SlotId;
        std::cerr<< "ConnectCard" <<std::endl;
        ConnectCard(reader_nb);
        std::cerr<< "StatusCard" <<std::endl;
        StatusCard();
        std::cerr<< "GettingAllCerts" <<std::endl;
        GettingAllCerts(keyfileData);
        std::cerr<< "FinishClean" <<std::endl;
        FinishClean();
        std::cerr<< "EMV Part DONE!!!" <<std::endl;
    }

    bool EMVToken::IsKeyfilePathValid (const wstring &securityTokenKeyfilePath) {
        return securityTokenKeyfilePath.find (TC_EMV_TOKEN_KEYFILE_URL_PREFIX) == 0;
    }


}