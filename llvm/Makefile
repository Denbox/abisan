CXX := clang++
CXXFLAGS := -ggdb -Wall -Wextra -Wpedantic -Wvla -Wshadow -fsanitize=address,undefined

.PHONY: all clean

all: abisan_llvm

abisan_llvm: abisan_llvm.cpp
	$(CXX) $(CFLAGS) $$(llvm-config --cxxflags --ldflags --libs all) $$(llvm-config --system-libs) $^ -o $@

clean:
	rm -f abisan_llvm

fmt:
	clang-format -i --style='{ColumnLimit: 0, IndentWidth: 4, AllowShortFunctionsOnASingleLine: false}' *.?pp
