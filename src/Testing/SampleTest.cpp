
#include "Testing.h"
#include "SampleTest.h"

using namespace VeraCrypt;

static bool functionDidRaise = true;
static bool functionWasRun = true;

void exceptionalTest(shared_ptr<VeraCrypt::TestResult> r) {
    r->Phase("throwing exception");
    functionWasRun = true;
    throw std::invalid_argument("intentionally raised exception within test");
    functionDidRaise = false;
}

void failedAssertionTest(shared_ptr<VeraCrypt::TestResult> r) {
    r->Failed("intentionally failed without exception");
}

int main() {
    VeraCrypt::Testing t;

    auto classTest = new SampleTest("sample");
    t.AddTest(classTest);
    t.AddTest("failing test", failedAssertionTest);
    t.AddTest("functional sample test", &exceptionalTest);

    t.Main();

    
    if (!classTest->WasRun) {
        cerr << "Test was not run" << endl;
        std::exit(1);
    }

    if (!functionWasRun) {
        cerr << "Test was not run" << endl;
        std::exit(1);
    }
    if (!functionDidRaise) {
        cerr << "Test did not raise as expected";
        std::exit(1);
    }

}