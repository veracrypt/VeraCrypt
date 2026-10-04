#ifndef TC_HEADER_Testing
#define TC_HEADER_Testing

#include <memory>
#include <vector>
#include <stdexcept>
#include <iostream>

#define DECORATE(msg) ">>>>> " << msg << " <<<<<"

using namespace std;

namespace VeraCrypt
{
    class TestFailedException : public std::exception {
        public:
            virtual const char * what () const noexcept {
                return "test failed";
            }

    };

    class TestResult {
        public:
            TestResult(string testName) : failed(false), testName(testName) { };
            void Phase(string msg) { phaseMsgs.push_back(msg); };

            void Success() { };
            void Failed(string reason, const exception &e) { Failed(reason + ": " + e.what()); };
            void Failed(string reason) { failReason = reason; failed = true; throw TestFailedException(); }
            void MarkFailed(string reason) { failReason = reason; failed = true; }

            void Info(string s) { cout <<  "[" << testName << "] " << s << endl; };
            

            bool IsSuccess() { return !failed; };
            bool IsFailed() { return failed; };
            string GetName() { return testName; };
            string GetFailureReason() { return failReason; }
            vector<string> GetPhases() { return phaseMsgs; };
        private:
            string failReason;
            bool failed;
            string testName;
            vector<string> phaseMsgs;
    };
    
    using testFunc = void (*)(shared_ptr<TestResult>);

    template<typename T>
    using paramTestFunc = void (*)(shared_ptr<TestResult>, T *);

    class Test {
        public:
            Test(string name) : name(name) {};
            virtual ~Test() {}
            
            virtual void Run(shared_ptr<TestResult> r) = 0;
            
            string GetName() { return name; };
        protected:
            string name;

    };

    class FunctionalTest : public Test {
        public:
            FunctionalTest(string name, testFunc func) : Test(name), func(func){};
            void Run(shared_ptr<TestResult> r) { func(r); }

        private:
            testFunc func;

    };

    template <typename P>
    class ParameterizedFunctionalTest : public Test {
        public:
            ParameterizedFunctionalTest(string name, paramTestFunc<P> func, P *param);
            void Run(shared_ptr<TestResult> r) { func(r, param); }
        private:
            paramTestFunc<P> func;
            P *param;
    };

    
    template<typename P>
    inline ParameterizedFunctionalTest<P>::ParameterizedFunctionalTest(string name, paramTestFunc<P> func, P *param)
    : Test(name), func(func), param(param) {

    };

    class TestSuite : public Test {
        public:
            TestSuite() : Test("<base>") { };
            void AddTest(Test* test);
            void AddTest(string name, testFunc func);
            void AddTest(TestSuite* suite, bool rollUp);
            

            template<typename P>
            static ParameterizedFunctionalTest<P> *param(string name, paramTestFunc<P> func, P *arg) { return new ParameterizedFunctionalTest<P>(name, func, arg); }

            void Run(shared_ptr<TestResult> r);

            vector<TestResult> GetResults() { return results; }
            void StopOnFirstFailure() { stopOnFirstFailure = true; }

        protected:
            shared_ptr<TestResult> RunSingle(Test *t);

        private:
            bool stopOnFirstFailure = false;
            vector<unique_ptr<Test> > tests;
            vector<TestResult> results;
    };

    class Testing : public TestSuite {
        public:
            Testing() : TestSuite() {};
            int Main();
            void Report();
    };

};

#endif