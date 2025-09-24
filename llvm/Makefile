CXX := clang++
CXXFLAGS := -g -Wall -Wextra -pedantic -Wvla -Wshadow

abisan_llvm: abisan_llvm.cpp
	$(CXX) $(CFLAGS) $$(llvm-config --cxxflags --ldflags --libs all) $$(llvm-config --system-libs) $^ -o $@
