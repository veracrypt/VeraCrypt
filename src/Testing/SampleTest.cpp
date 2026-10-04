#include "Testing.h"
#include "SampleTest.h"

using namespace VeraCrypt;

static void FailedAssertion(shared_ptr<TestResult> result)
{
    result->Failed("expected assertion failure");
}

static void StandardException(shared_ptr<TestResult>)
{
    throw std::invalid_argument("expected exception");
}

static void UnknownException(shared_ptr<TestResult>)
{
    throw 42;
}

static void BareFailure(shared_ptr<TestResult>)
{
    throw TestFailedException();
}

static void CheckFailureHandling(shared_ptr<TestResult> result)
{
    TestSuite suite;
    suite.AddTest("assertion", FailedAssertion);
    suite.AddTest("standard exception", StandardException);
    suite.AddTest("unknown exception", UnknownException);
    suite.AddTest("bare failure", BareFailure);
    auto aggregate = make_shared<TestResult>("expected failures");
    suite.Run(aggregate);
    if (!aggregate->IsFailed() || suite.GetResults().size() != 4)
        result->Failed("Failures were not reported by the suite");
    for (const auto &entry : suite.GetResults()) {
        TestResult outcome(entry);
        if (!outcome.IsFailed())
            result->Failed("A failing test was reported as passing");
    }

    suite.Run(aggregate);
    if (suite.GetResults().size() != 4)
        result->Failed("Repeated runs retained stale results");
}

static void CheckNestedFailure(shared_ptr<TestResult> result)
{
    TestSuite suite;
    TestSuite *nested = new TestSuite();
    nested->AddTest("nested failure", FailedAssertion);
    suite.AddTest(nested);
    auto aggregate = make_shared<TestResult>("nested suite");
    suite.Run(aggregate);
    if (!aggregate->IsFailed())
        result->Failed("Nested failure did not reach the parent suite");
}

static void CheckStopOnFailure(shared_ptr<TestResult> result)
{
    TestSuite suite;
    suite.StopOnFirstFailure();
    suite.AddTest("failure", FailedAssertion);
    SampleTest *unreached = new SampleTest("unreached");
    suite.AddTest(unreached);
    auto aggregate = make_shared<TestResult>("stop on failure");
    suite.Run(aggregate);
    if (!aggregate->IsFailed() || unreached->WasRun || suite.GetResults().size() != 1)
        result->Failed("Stop-on-failure did not stop the suite");
}

int main()
{
    Testing tests;
    tests.AddTest(new SampleTest("successful test"));
    tests.AddTest("failure and exception reporting", CheckFailureHandling);
    tests.AddTest("nested suite failures", CheckNestedFailure);
    tests.AddTest("stop on first failure", CheckStopOnFailure);
    return tests.Main();
}
