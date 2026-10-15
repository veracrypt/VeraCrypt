// Standalone cleanup checks using synthetic data; no smart card is required.
// c++ -std=c++11 -O2 -Isrc Tests/response_apdu_test.cpp \
//     src/Common/ResponseAPDU.cpp src/Common/TLVParser.cpp -o /tmp/response_apdu_test
#include "Common/ResponseAPDU.h"
#include "Common/TLVParser.h"
#include <cstdio>
#include <cstdlib>
#include <new>
#include <type_traits>
#include <utility>

using namespace VeraCrypt;

static const void *watched = NULL;
static size_t watchedSize = 0;
static unsigned int wipesChecked = 0;
static bool failNextAllocation = false;

static void Require(bool condition, const char *message)
{
	if (!condition)
	{
		std::fprintf(stderr, "FAIL: %s\n", message);
		std::abort();
	}
}

void *operator new(size_t size)
{
	if (failNextAllocation)
	{
		failNextAllocation = false;
		throw std::bad_alloc();
	}
	void *p = std::malloc(size ? size : 1);
	if (!p) throw std::bad_alloc();
	return p;
}

void operator delete(void *p) noexcept
{
	if (p && p == watched)
	{
		// Inspect while storage is still allocated, before forwarding to free().
		const unsigned char *bytes = static_cast<const unsigned char *>(p);
		for (size_t i = 0; i < watchedSize; ++i)
			Require(bytes[i] == 0, "response storage released without erasure");
		watched = NULL;
		++wipesChecked;
	}
	std::free(p);
}

#if __cplusplus >= 201402L
void operator delete(void *p, size_t) noexcept { ::operator delete(p); }
#endif

static void Watch(const ResponseAPDU& response)
{
	Require(watched == NULL && !response.getData().empty(), "invalid cleanup observation");
	watched = response.getData().data();
	watchedSize = response.getData().size();
}

int main()
{
	static_assert(std::is_same<decltype(std::declval<const ResponseAPDU&>().getData()),
		const vector<uint8>&>::value, "getData must not copy response bytes");
	const vector<uint8> original(37, 0x5a);
	const vector<uint8> suffix(7, 0x23);

	{
		ResponseAPDU response(original, 0x9000);
		Watch(response);
		response.clear();
		Require(response.getData().empty() && response.getSW() == 0, "clear changed semantics");
		response.appendData(suffix);
		Require(response.getData() == suffix, "reuse after clear");
		// The original tail must also have been wiped, even though size is now smaller.
	}
	{
		ResponseAPDU response(original, 0x9000);
		const vector<uint8> extra(response.getData().capacity() + 1, 0x23);
		Watch(response);
		response.appendData(extra);
		Require(watched == NULL, "growth did not release old storage");
		Require(response.getData().size() == original.size() + extra.size(), "append size");
		for (size_t i = 0; i < response.getData().size(); ++i)
			Require(response.getData()[i] == (i < original.size() ? 0x5a : 0x23), "append contents");
		Watch(response);
	}
	{
		ResponseAPDU response(original, 0x9000);
		response.appendData(response.getData());
		Require(response.getData() == vector<uint8>(original.size() * 2, 0x5a), "aliased append");
		response.clear();
		response.appendData(suffix);
		response.appendData(response.getData());
		Require(response.getData() == vector<uint8>(suffix.size() * 2, 0x23), "aliased append with capacity");
		Watch(response);
	}
	{
		ResponseAPDU source(original, 0x9000), target(suffix, 0x6a82);
		Watch(target);
		target = source;
		Require(watched == NULL && target.getData() == original && target.getSW() == 0x9000, "copy assignment");
		ResponseAPDU copy(target);
		target.clear();
		Require(copy.getData() == original, "copy must own its storage");
		ResponseAPDU& alias = copy;
		copy = alias;
		Require(copy.getData() == original, "self assignment");
		Watch(copy);
	}
	{
		ResponseAPDU source(original, 0x9000), target(suffix, 0x6a82);
		vector<uint8> encoded = source.getBytes();
		Watch(target);
		target.setBytes(encoded);
		Require(watched == NULL && target.getData() == original && target.getSW() == 0x9000, "response round trip");
		ResponseAPDU alias(encoded, 0);
		alias.setBytes(alias.getData());
		Require(alias.getData() == original && alias.getSW() == 0x9000, "aliased setBytes");
		Watch(target);
		target.setBytes(vector<uint8>(1, 0));
		Require(watched == NULL && target.getData().empty() && target.getSW() == 0, "short response");
	}
	{
		ResponseAPDU response(original, 0x9000), target(suffix, 0x6a82);
		const vector<uint8> extra(response.getData().capacity() + 1, 0x23);
		failNextAllocation = true;
		try { response.appendData(extra); Require(false, "expected allocation failure"); }
		catch (const std::bad_alloc&) {}
		Require(response.getData() == original && response.getSW() == 0x9000, "failed growth changed response");
		failNextAllocation = true;
		try { target = response; Require(false, "expected allocation failure"); }
		catch (const std::bad_alloc&) {}
		Require(target.getData() == suffix && target.getSW() == 0x6a82, "failed assignment changed response");
		Watch(response);
	}
	try
	{
		ResponseAPDU response(original, 0x9000);
		Watch(response);
		throw 1;
	}
	catch (int) {}
	{
		const uint8 encoded[] = { 0x5a, 0x02, 0x12, 0x34 };
		ResponseAPDU response(vector<uint8>(encoded, encoded + sizeof(encoded)), 0x9000);
		shared_ptr<TLVNode> node = TLVParser::TLV_Parse(response.getData().data(), response.getData().size());
		response.clear();
		Require(node->Tag == 0x5a && node->Value->size() == 2
			&& (*node->Value)[0] == 0x12 && (*node->Value)[1] == 0x34, "parser retained borrowed storage");
	}
	Require(watched == NULL && wipesChecked == 10, "missing cleanup observations");
	std::puts("PASS: response ownership, erasure before release, replacement, growth, aliasing, allocation failure, unwinding and const TLV input");
}
