#ifndef TC_HEADER_Common_TLVPARSER
#define TC_HEADER_Common_TLVPARSER

#include "Platform/PlatformBase.h"
#include "Tcdefs.h"

namespace VeraCrypt
{
	struct TLVNode
	{
		uint16 Tag;							/*	T 	*/
		uint16 Length;						/*	L 	*/
		shared_ptr<vector<byte>> Value;		/*	V 	*/
		byte TagSize;
		byte LengthSize;
		uint16 MoreFlag;					/* Used In Sub */
		uint16 SubFlag;						/* Does it have sub-nodes? */
		shared_ptr<vector<shared_ptr<TLVNode>>> Subs;

		TLVNode() : Tag(0), Length(0), TagSize(0), LengthSize(0), MoreFlag(0), SubFlag(0)
		{
			Value = make_shared<vector<byte>>();
			Subs = make_shared<vector<shared_ptr<TLVNode>>>();
		}

		~TLVNode()
		{
			burn(Value->data(), Value->size());
		}
	};

	class TLVParser
	{
	private :

		/* TLV node structure creation */
		static shared_ptr<TLVNode> TLV_CreateNode();

		/* Check if the bit is correct */
		static uint16 CheckBit(byte value, int bit);

		/* Parsing one TLV node */
		static shared_ptr<TLVNode> TLV_Parse_One(byte* buf, size_t size);

		/* Parsing all TLV nodes */
		static int TLV_Parse_SubNodes(shared_ptr<TLVNode> parent);

		/* Parsing all sub-nodes (in width not in depth) of a given parent node */
		static int TLV_Parse_All(shared_ptr<TLVNode> parent);

		/* Recursive function to parse all nodes starting from a root parent node */
		static void TLV_Parse_Sub(shared_ptr<TLVNode> parent);

	public:

		/* Parsing TLV from a buffer and constructing TLV structure */
		static shared_ptr<TLVNode> TLV_Parse(byte* buf, size_t size);

		/* Finding a TLV node with a particular tag */
		static shared_ptr<TLVNode> TLV_Find(shared_ptr<TLVNode> node, uint16 tag);
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
}

#endif //TC_HEADER_Common_TLVPARSER
