#include "Testing.h"
#include <iostream>

using namespace std;

namespace VeraCrypt {

    void Testing::Main() {
        auto r = make_shared<TestResult>(this->GetName());
        Run(r);
        Report();
    };

    void Testing::Report() {
        size_t passed = 0;
        size_t failed = 0;
        auto results = GetResults();
        cout << endl;
        cout << DECORATE("TESTS SUMMARY") << endl;
        for (auto t = results.begin(); t != results.end(); ++t) {
            if (t->IsSuccess()) {
                cout << ".";
                passed ++;
            } else {
                cout << "E";
                failed ++;
            }
        }
        cout << endl;
        cout << passed << " passed, " << failed << " failed" << endl;

        if (failed > 0) {
            cout << DECORATE("Failed test details:") << endl;
        }
        for (auto t = results.begin(); t != results.end(); ++t) {
            if (t->IsFailed()) {
                cout << "* " << t->GetName() << endl;
                cout << "  " << t->GetFailureReason() << endl;
                auto phases = t->GetPhases();
                if (phases.size() > 0) {
                    cout << "  Phases:" << endl;
                    for (auto phaseName = phases.begin(); phaseName != phases.end(); ++phaseName) {
                        cout <<  "  - " << *phaseName << endl;
                    }
                }
            }
        }
        cout << endl;
    }

    shared_ptr<TestResult> TestSuite::RunSingle(Test *t) {
        shared_ptr<TestResult> result = shared_ptr<TestResult>(new TestResult(t->GetName()));
        try {
            t->Run(result);
        } catch (TestFailedException& e) {
        } catch (const exception& e) {
            result->MarkFailed("Test case threw exception: " + string(e.what()));
        }
        return result;
    };

    void TestSuite::Run(shared_ptr<TestResult> res) {
        try {
            for (auto t = tests.begin(); t != tests.end(); ++t) {
                auto r = RunSingle(*t);
                results.push_back(*r);
                if (r->IsFailed()) {
                    res->MarkFailed(r->GetFailureReason());
                }
                if (stopOnFirstFailure && r->IsFailed()) {
                    return;
                }
            }
        } catch (const exception &e) {
            cerr << "Testing system failure: " << e.what() << endl;
        } catch (...) {
            cerr << "Testing system failure" << endl;
        }
    }

    void TestSuite::AddTest(Test *test) {
        tests.push_back(test);
    };

    void TestSuite::AddTest(string name, testFunc func) {
        AddTest(new FunctionalTest(name, func));
    };

    void TestSuite::AddTest(TestSuite *suite, bool rollUp) {
        suite->MarkRollUp();
        tests.push_back(suite);
    }

};