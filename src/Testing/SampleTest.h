/*
 Copyright (c) 2024-2025 Anton Dubenchuk.
 Modifications and additions Copyright (c) 2026 AM Crypto.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include <iostream>

#include "Testing.h"

namespace VeraCrypt {


    class SampleTest : public Test {
        public:
            SampleTest(string name) : Test(name), WasRun(false) {};
            void Run(shared_ptr<TestResult> r) { WasRun = true; };
            bool WasRun;
    };

};