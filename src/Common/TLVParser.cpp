#include "TLVParser.h"
#include <string.h>

using namespace std;

namespace VeraCrypt
{
	/* TLV node structure creation */
	shared_ptr<TLVNode> TLVParser::TLV_CreateNode()
	{
		shared_ptr<TLVNode> node = shared_ptr<TLVNode>(new TLVNode());
		return node;
	}

	/* Check if the bit is correct */
	uint16 TLVParser::CheckBit(uint8 value, int bit)
	{
		unsigned char bitvalue[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

		if ((bit >= 1) && (bit <= 8))
		{
			if (value & bitvalue[bit-1])
			{
				return (1);
			}
			else
			{
				return (0);
			}
		}
		else
		{
			throw TLVException("FILE:"+string(__FILE__)+"LINE: "+to_string(static_cast<long long>((__LINE__)))+" fonction parameter incorrect! bit=["+to_string(static_cast<long long>(bit)));
			//return(2);
		}
	}

	/* Parsing one TLV node */
	shared_ptr<TLVNode> TLVParser::TLV_Parse_One(uint8* buf, size_t size)
	{
		size_t index = 0;
		size_t i = 0;
		uint8 tag1, tag2, tagsize;
		uint8 len, lensize;
		shared_ptr<vector<uint8>> value = make_shared<vector<uint8>>();
		shared_ptr<TLVNode> node = TLV_CreateNode();

		tag1 = tag2 = 0;
		tagsize = 1;
		tag1 = buf[index++];
		if ((tag1 & 0x1f) == 0x1f)
		{
			tagsize++;
			tag2 = buf[index++];
			//tag2 b8 must be 0!
		}
		if (tagsize == 1)
		{
			node->Tag = tag1;
		}
		else
		{
			node->Tag = (tag1 << 8) + tag2;
		}
		node->TagSize = tagsize;

		//SubFlag
		node->SubFlag = CheckBit(tag1,6);

		//L zone
		len = 0;
		lensize = 1;
		len = buf[index++];
		if (CheckBit(len,8) == 0)
		{
			node->Length = len;
		}
		else
		{
			lensize = len & 0x7f;
			len = 0;
			for (i = 0; i < lensize; i++)
			{
				len += (uint16)buf[index++] << (i*8);
			}
			lensize++;
		}
		node->Length = len;
		node->LengthSize = lensize;

		//V zone
		value->resize(len);
		memcpy(value->data(), buf + index, len);
		node->Value = value;
		index += len;

		if (index < size)
		{
			node->MoreFlag = 1;
		}
		else if(index == size)
		{
			node->MoreFlag = 0;
		}
		else
		{
			throw TLVException("Parse Error! index="+to_string(static_cast<long long>(index))+"size="+to_string(static_cast<long long>(size)));
		}

		return node;
	}

	/* Parsing all sub-nodes (in width not in depth) of a given parent node */
	int TLVParser::TLV_Parse_SubNodes(shared_ptr<TLVNode> parent)
	{
		uint16 sublen = 0;
		size_t i;

		//No sub-nodes
		if (parent->SubFlag == 0)
			return 0;

		for (i = 0; i < parent->Subs->size(); i++)
		{
			sublen += (parent->Subs->at(i)->TagSize + parent->Subs->at(i)->Length + parent->Subs->at(i)->LengthSize);
		}

		if (sublen < parent->Value->size())
		{
			shared_ptr<TLVNode> subnode = TLV_Parse_One(parent->Value->data() + sublen, parent->Value->size() - sublen);
			parent->Subs->push_back(subnode);
			return subnode->MoreFlag;
		}
		else
		{
			return 0;
		}
	}

	/* Recursive function to parse all nodes starting from a root parent node */
	void TLVParser::TLV_Parse_Sub(shared_ptr<TLVNode> parent)
	{
		size_t i;
		if (parent->SubFlag != 0)
		{
			// Parse all sub nodes.
			while (TLV_Parse_SubNodes(parent) != 0);

			for (i = 0; i < parent->Subs->size(); i++)
			{
				if (parent->Subs->at(i)->SubFlag != 0)
				{
					TLV_Parse_Sub(parent->Subs->at(i));
				}
			}
		}
	}

	/* Parsing TLV from a buffer and constructing TLV structure */
	shared_ptr<TLVNode> TLVParser::TLV_Parse(uint8* buf, size_t size)
	{
		shared_ptr<TLVNode> node = TLV_Parse_One(buf, size);
		TLV_Parse_Sub(node);

		return node;
	}

	/* Finding a TLV node with a particular tag */
	shared_ptr<TLVNode> TLVParser::TLV_Find(shared_ptr<TLVNode> node, uint16 tag)
	{
		size_t i = 0;
		shared_ptr<TLVNode> tmpnode;
		if (node->Tag == tag)
		{
			return node;
		}
		for (i = 0; i < node->Subs->size(); i++)
		{
			tmpnode = TLV_Find(node->Subs->at(i),tag);
			if (tmpnode)
			{
				return tmpnode;
			}
		}
		return shared_ptr<TLVNode>();
	}
}
