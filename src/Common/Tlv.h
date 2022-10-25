#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>



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
static struct TLVNode* TLV_CreateNode(void);

/* Check if the bit is correct */
static inline int CheckBit(unsigned char value, int bit);

/* Parsing one TLV node */
static struct TLVNode* TLV_Parse_One(unsigned char* buf,int size);

/* Parsing all TLV nodes */
static int TLV_Parse_SubNodes(struct TLVNode* parent);

/* Parsing all sub-nodes (in width not in depth) of a given parent node */
static int TLV_Parse_All(struct TLVNode* parent);

/* Recursive function to parse all nodes starting from a root parent node */
static void TLV_Parse_Sub(struct TLVNode* parent);

/* Parsing TLV from a buffer and constructing TLV structure */
struct TLVNode* TLV_Parse(unsigned char* buf,int size);

/* Finding a TLV node with a particular tag */
struct TLVNode* TLV_Find(struct TLVNode* node,uint16_t tag);

