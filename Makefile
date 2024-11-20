# Aplication options
APP = $(notdir $(CURDIR))# Application name is name of root holder
GXX_STANDARD = 20 # 11, 14, 17, 20
OUT_FILE_NAME = $(APP)

# Compiler options
CC = g++
CXXFLAGS = -Wall -Wextra -std=c++$(GXX_STANDARD)
CXXFLAGS += -Wc++0x-compat -Wc++11-compat -Wc++14-compat -Waggressive-loop-optimizations -Walloc-zero -Walloca -Walloca-larger-than=8192 -Warray-bounds -Wchar-subscripts -Wconditionally-supported -Wconversion -Wctor-dtor-privacy -Wdangling-else -Wduplicated-branches -Wempty-body -Wfloat-equal -Wformat-nonliteral -Wformat-security -Wformat-signedness -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 -Winline -Wlarger-than=8192 -Wvla-larger-than=8192 -Wlogical-op -Wmissing-declarations -Wnon-virtual-dtor -Wopenmp-simd -Woverloaded-virtual -Wpacked -Wpointer-arith -Wredundant-decls -Wrestrict -Wshadow -Wsign-promo -Wstack-usage=8192 -Wstrict-null-sentinel -Wstrict-overflow=2 -Wstringop-overflow=4 -Wsuggest-attribute=noreturn -Wsuggest-final-types -Wsuggest-override -Wswitch-default -Wswitch-enum -Wsync-nand -Wundef -Wunreachable-code -Wunused -Wvariadic-macros -Wno-literal-suffix -Wno-missing-field-initializers -Wnarrowing -Wno-old-style-cast -Wvarargs -Waligned-new -Walloc-size-larger-than=1073741824 -Walloc-zero -Walloca -Walloca-larger-than=8192 -Wdangling-else -Wduplicated-branches -Wformat-overflow=2 -Wformat-truncation=2 -Wmissing-attributes -Wmultistatement-macros -Wrestrict -Wshadow=global -Wsuggest-attribute=malloc -fcheck-new -fsized-deallocation -fstrict-overflow -flto-odr-type-merging -fno-omit-frame-pointer
CXXFLAGS += -fPIE # For plugin
CXXFLAGS += --static
LXXFLAGS = --static
BUILD = Debug

# ------------------------------------------------------------------------------------------

# Library options
LIBS = #SSE #SFML

# Activate SSE
ifeq ($(filter SSE, $(LIBS)), SSE)
	CXXFLAGS += -mavx -mavx2
endif

# Include library
LIB_PATH =
LIB_DEPEND = #boost_program_options

# Include SFML
ifeq ($(filter SFML, $(LIBS)), SFML)
	LIB_PATH += 
	LIB_DEPEND += sfml-audio  sfml-graphics  sfml-network  sfml-system  sfml-window
endif

# Set library flags
CXXFLAGS += $(patsubst %,-I%/include,$(LIB_PATH))
LXXFLAGS += $(patsubst %,-L%/lib,$(LIB_PATH)) $(addprefix -l, $(LIB_DEPEND))

# ------------------------------------------------------------------------------------------

# Set name folder
SRC_DIR = src
BIN_DIR = bin
# SHARED_DIR = ../Shared
# SHARED_OBJ = $(shell find ./$(SHARED_DIR)/bin -name "*.o")

# Search for source files
SRC_FULL_PATH = $(shell find ./$(SRC_DIR)/ -name "*.cpp")
OBJ = $(addprefix $(BIN_DIR)/, $(SRC:.cpp=.o))
EXLUDED = # Excluded files
SRC = $(filter-out $(EXLUDED),$(notdir $(SRC_FULL_PATH)))
DEPENDENS = $(addprefix $(BIN_DIR)/, $(SRC:.cpp=.d))


# ------------------------------------------------------------------------------------------

# Setting build parameters
ifeq ($(BUILD), Debug)
	CXXFLAGS += -O1 -g -fdiagnostics-color=always
	BUILD_PATH = build-debug

	OBJ = $(addprefix $(BIN_DIR)/, $(SRC:.cpp=d.o))
	DEPENDENS = $(addprefix $(BIN_DIR)/, $(SRC:.cpp=d.d))
else
	CXXFLAGS += -Os -s -DNDEBUG
	BUILD_PATH = build-release
endif

# ------------------------------------------------------------------------------------------

# Set include path
CXXFLAGS += -I$(CURDIR)
CXXFLAGS += -I$(CURDIR)/src
CXXFLAGS += -I$(CURDIR)/../Shared

# Сonfiguring file search paths
VPATH = $(dir $(SRC_FULL_PATH))

# ------------------------------------------------------------------------------------------
# Main build Rule
build: buildInfo $(BUILD_PATH)/$(OUT_FILE_NAME)

# ------------------------------------------------------------------------------------------

# Print build info
buildInfo:
	@echo "Start compile $(APP) in $(BUILD) mode"
#echo $(CXXFLAGS)

# Build project 
$(BUILD_PATH)/$(OUT_FILE_NAME): $(OBJ) Makefile
	@mkdir -p $(BUILD_PATH)
	@$(CC) $(OBJ) $(SHARED_OBJ) -o $(BUILD_PATH)/$(OUT_FILE_NAME) $(LXXFLAGS)

# Dependency checking
-include $(DEPENDENS)

# Compilation source 
$(BIN_DIR)/%.o: %.cpp Makefile
	@echo "[ Compile $< ($(BUILD))]"
	@$(CC) $< -c -o $@ $(CXXFLAGS)

# Compilation source for debug
$(BIN_DIR)/%d.o: %.cpp Makefile
	@echo "[$< ($(BUILD))]"
	@$(CC) $< -c -o $@ $(CXXFLAGS)

# Updating dependencies
$(BIN_DIR)/%.d: %.cpp Makefile
	@mkdir -p bin
	@$(CC) $< -MM -MT '$(BIN_DIR)/$*.o $(BIN_DIR)/$*.d' -MF $@ $(CXXFLAGS)

# Updating dependencies for debug
$(BIN_DIR)/%d.d: %.cpp Makefile
	@mkdir -p bin
	@$(CC) $< -MM -MT '$(BIN_DIR)/$*d.o $(BIN_DIR)/$*d.d' -MF $@ $(CXXFLAGS)

# ------------------------------------------------------------------------------------------
.PHONY: init gitInit clean
init: gitInit
	@mkdir -p bin

gitInit:
	@echo "  [Init git repository]"
	@echo -n "    "
	@git init
	@git add .
	@git commit -m "init commit"

clean:
	echo "  [Clean all build file]"
	@rm -r bin