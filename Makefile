# Path to Visual Studio Developer Command Prompt script
VS_DEV_CMD := "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

# Compilers and flags
CXX_MSVC := cl
CXX_GCC := g++
CXXFLAGS_MSVC := /LD /W4 /std:c++17
CXXFLAGS_GCC := -std=c++11 -Wall -static-libstdc++ -static-libgcc -static
LIBS := User32.lib

# Target executable and DLL
INJECTOR := injector.exe
DLL_TARGET := ./dll/apihook.dll
INJECTOR_SOURCES := src/injector.cpp
DLL_SOURCES := resource/apihook.cpp

# Rule to build both targets
all: $(DLL_TARGET) $(INJECTOR)

# Rule to build the DLL using the batch file
$(DLL_TARGET): $(DLL_SOURCES)
	@echo "Building DLL"
	@cmd /c build_dll.bat

# Rule to build the injector using g++
$(INJECTOR): $(INJECTOR_SOURCES)
	@echo Building injector
	$(CXX_GCC) $(CXXFLAGS_GCC) -o $@ $^

# Clean up
clean:
	@echo Cleaning up
	rm -f $(INJECTOR) $(DLL_TARGET) *.obj *.o 2>/dev/null || true

.PHONY: all clean
