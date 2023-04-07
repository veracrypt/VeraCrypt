//
// Created by bshp on 1/20/23.
//

#ifndef ICC_EXTRACTOR_TLVPARSER_H
#define ICC_EXTRACTOR_TLVPARSER_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <string>
#include <memory>
#include "iostream"
#include "Tcdefs.h"
using namespace std;
struct TLVNode{
	uint16_t Tag;				/*	T 	*/
	uint16_t Length;			/*	L 	*/
	unsigned char* Value;		/*	V 	*/
	unsigned char TagSize;
	unsigned char LengthSize;
	uint16_t MoreFlag;			/* Used In Sub */
	uint16_t SubFlag;			/* Does it have sub-nodes? */
	uint16_t SubCount;
	shared_ptr<TLVNode> Sub[256];
	shared_ptr<TLVNode> Next;

	~TLVNode() {
        burn(Value, Length);
        delete Value;
	}
};

class TLVParser{
private :

	/* TLV node structure creation */
	static shared_ptr<TLVNode> TLV_CreateNode();

	/* Check if the bit is correct */
	static uint16_t CheckBit(unsigned char value, int bit);

	/* Parsing one TLV node */
	static shared_ptr<TLVNode> TLV_Parse_One(unsigned char* buf,int size);

	/* Parsing all TLV nodes */
	static int TLV_Parse_SubNodes(shared_ptr<TLVNode> parent);

	/* Parsing all sub-nodes (in width not in depth) of a given parent node */
	static int TLV_Parse_All(shared_ptr<TLVNode> parent);

	/* Recursive function to parse all nodes starting from a root parent node */
	static void TLV_Parse_Sub(shared_ptr<TLVNode> parent);

public:

	/* Parsing TLV from a buffer and constructing TLV structure */
	static shared_ptr<TLVNode> TLV_Parse(unsigned char* buf,int size);

	/* Finding a TLV node with a particular tag */
	static shared_ptr<TLVNode> TLV_Find(shared_ptr<TLVNode> node,uint16_t tag);
};

/* The definition of the exception class related to the TLV parsing */
class TLVException
{
public:
	TLVException(std::string errormessage): m_errormessage(errormessage){}

	/* Get the error message */
	inline std::string ErrorMessage() const
	{
		return m_errormessage;
	}

protected:
	std::string m_errormessage;
};

#endif //ICC_EXTRACTOR_TLVPARSER_H
