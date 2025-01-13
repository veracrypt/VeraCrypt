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