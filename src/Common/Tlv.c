#include "Tlv.h"
#include <string.h>


/* TLV node structure creation */
struct TLVNode* TLV_CreateNode(void)
{
    struct TLVNode* node = (struct TLVNode *)malloc(sizeof(*node));
    memset(node,0,sizeof(*node));
    return node;
}

/* Check if the bit is correct */
inline int CheckBit(unsigned char value, int bit){
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
struct TLVNode* TLV_Parse_One(unsigned char* buf,int size){
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
int TLV_Parse_SubNodes(struct TLVNode* parent){
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
void TLV_Parse_Sub(struct TLVNode* parent)
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