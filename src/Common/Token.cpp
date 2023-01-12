#include "Token.h"
#include "Platform/Finally.h"
#include "Platform/ForEach.h"

#if !defined(TC_WINDOWS) || defined(TC_PROTOTYPE)
#include "Platform/SerializerFactory.h"
#include "Platform/StringConverter.h"
#include "Platform/SystemException.h"
#else
#include "Dictionary.h"
#include "Language.h"
#endif

#include <vector>
#include <algorithm>
#include <memory>

#include "SecurityToken.h"
#include "EMVToken.h"


using namespace std;

namespace VeraCrypt
{
    vector<unique_ptr<TokenKeyfile>> Token::GetAvailableKeyfiles() {
        vector<SecurityTokenKeyfile> v1 = SecurityToken::GetAvailableKeyfiles();
        vector<EMVTokenKeyfile> v2 = EMVToken::GetAvailableKeyfiles();

        vector<unique_ptr<TokenKeyfile>> v_ptr;
        v_ptr.resize(v1.size() + v2.size());

        for (SecurityTokenKeyfile& k : v1) {
            v_ptr.push_back(make_unique<SecurityTokenKeyfile>(k));
        }

        for (auto& k : v2) {
            v_ptr.push_back(make_unique<EMVTokenKeyfile>(k));
        }

        return v_ptr;

    }
}