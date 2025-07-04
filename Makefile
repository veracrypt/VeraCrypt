CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra

all: prng_translator prng_translator_optimized

prng_translator: prng_translator.cpp
	$(CXX) $(CXXFLAGS) -o prng_translator prng_translator.cpp

prng_translator_optimized: prng_translator_optimized.cpp
	$(CXX) $(CXXFLAGS) -o prng_translator_optimized prng_translator_optimized.cpp

clean:
	rm -f prng_translator prng_translator_optimized

test: prng_translator_optimized
	./prng_translator_optimized | head -10

.PHONY: all clean test
