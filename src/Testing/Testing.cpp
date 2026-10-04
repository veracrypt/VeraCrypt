/*
 Copyright (c) 2024-2025 Anton Dubenchuk.
 Modifications and additions Copyright (c) 2026 AM Crypto.

 Governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#include "Testing.h"
#include <iostream>

using namespace std;

namespace VeraCrypt {

    int Testing::Main() {
        auto r = make_shared<TestResult>(this->GetName());
        Run(r);
        Report();
        return r->IsSuccess() ? 0 : 1;
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
        } catch (const TestFailedException& e) {
            if (!result->IsFailed())
                result->MarkFailed(e.what());
        } catch (const exception& e) {
            result->MarkFailed("Test case threw exception: " + string(e.what()));
        } catch (...) {
            result->MarkFailed("Test case threw an unknown exception");
        }
        return result;
    };

    void TestSuite::Run(shared_ptr<TestResult> res) {
        results.clear();
        for (auto t = tests.begin(); t != tests.end(); ++t) {
            auto r = RunSingle(t->get());
            results.push_back(*r);
            if (r->IsFailed()) {
                res->MarkFailed(r->GetName() + ": " + r->GetFailureReason());
                if (stopOnFirstFailure)
                    return;
            }
        }
    }

    void TestSuite::AddTest(Test *test) {
        tests.push_back(unique_ptr<Test>(test));
    };

    void TestSuite::AddTest(string name, testFunc func) {
        AddTest(new FunctionalTest(name, func));
    };

    void TestSuite::AddTest(TestSuite *suite, bool rollUp) {
        AddTest(static_cast<Test*>(suite));
    }

};