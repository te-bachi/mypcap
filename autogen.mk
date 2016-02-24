
.SUFFIXES::
.PHONY:: all clean mkdirs Makefile autogen.mk
% :: ;

CROSS_COMPILE  =
CC             = $(CROSS_COMPILE)gcc
C++            = $(CROSS_COMPILE)c++
AR             = $(CROSS_COMPILE)ar
RANLIB         = $(CROSS_COMPILE)ranlib

SRC_FORMAT     = c
SRC_DIR        = src
OBJ_DIR        = obj

### Quiet-mode
ifneq ($(LOUD),)
  SILENT = 
else
  SILENT = @
endif

### HELP
# $(foreach var,list,text)      For each newly created variable 'var' in 'list',
#                               do whatever in 'text'
# $(call variable,param,...)    Call a defined subroutine
# $(1), $(2)                    Arguments of defined subroutines
# $(eval var)                   Expand 'var' and parse as makefile syntax
# $(var:pattern=replacement)    Substitutes 'var' with 'replacement'

### MKDIR FOR EVERY PROGRAM
#
define DIRECTORY_template

DIRECTORIES += $(OBJ_DIR)/$(1)

$(OBJ_DIR)/$(1):
	@echo "[MKDIR] $$@"
	$(SILENT)mkdir -p $(OBJ_DIR)/$(1)

endef

### VARIABLE FOR EVERY PROGRAM
#
define VARIABLE_template

$(1)_OBJECT = $(addprefix $(OBJ_DIR)/$(1)/,$($(1)_SOURCE:%.$(SRC_FORMAT)=%.o))

$(call DIRECTORY_template,$(1))
$(foreach dir, $(addprefix $(1)/,$(sort $(dir $($(1)_SOURCE)))), $(eval $(call DIRECTORY_template,$(dir))))

endef

### OBJECT FOR EVERY SOURCE FILE
define OBJECT_template

$(OBJ_DIR)/$(1)/$($(3):%.$(SRC_FORMAT)=%.o): $(2)/$($(3))
	@echo "[CC] $(2)/$($(3))"
	$(SILENT)$(CC) -o $$@ -c $(2)/$($(3)) $(GLOBAL_CFLAGS) $($(1)_CFLAGS)

endef

### PROGRAM
define PROGRAM_template

.PHONY:: $(1) $(1)_clean

$(foreach source,$($(1)_SOURCE),$(eval $(call OBJECT_template,$(1),$(SRC_DIR),source)))

$(1): $(OBJ_DIR)/$(1)/$(1)
#$(1): $($(1)_LIBRARIES:%=$(OBJ_DIR)/%/%) $(OBJ_DIR)/$(1)/$(1)
$(OBJ_DIR)/$(1)/$(1): $(OBJ_DIR)/$(1) $($(1)_OBJECT) $(foreach lib, $($(1)_LIBRARIES), $(OBJ_DIR)/$(lib)/$(lib))
	@echo "[LD] $$@"
	$(SILENT)$(CC) -o $$@ $($(1)_OBJECT) $($(1)_LIBRARIES:%=-L$(OBJ_DIR)/%) $($(1)_LIBRARIES:lib%.a=-l%) $(GLOBAL_LDFLAGS) $($(1)_LDFLAGS)

$(1)_clean:
	@echo "[CLEAR $(1)]"
	$(SILENT)rm -rf $($(1)_OBJECT) $(OBJ_DIR)/$(1)
endef

### LIBRARY
define LIBRARY_template

.PHONY:: $(1) $(1)_clean

$(foreach source,$($(1)_SOURCE),$(eval $(call OBJECT_template,$(1),$(SRC_DIR),source)))

$(1): $(OBJ_DIR)/$(1)/$(1)
$(OBJ_DIR)/$(1)/$(1): $(OBJ_DIR)/$(1) $($(1)_OBJECT)
	@echo "[AR] $$@"
	$(SILENT)$(AR) rc $$@ $($(1)_OBJECT)
	@echo "[RANLIB] $$@"
	$(SILENT)$(RANLIB) $$@

$(1)_clean:
	@echo "[CLEAR $(1)]"
	$(SILENT)rm -rf $($(1)_OBJECT) $(OBJ_DIR)/$(1)
endef


all: mkdirs $(LIBRARIES_STATIC) $(PROGRAMS)
clean: $(addsuffix _clean,$(LIBRARIES_STATIC)) $(addsuffix _clean,$(PROGRAMS))
	$(SILENT)if ([ -d "$(OBJ_DIR)" ] && [ -z "`ls -A $(OBJ_DIR)`" ]); then \
		rm -rf $(OBJ_DIR); \
	fi

$(foreach lib,   $(LIBRARIES_STATIC), $(eval $(call VARIABLE_template,$(lib))))
$(foreach lib,   $(LIBRARIES_STATIC), $(eval $(call LIBRARY_template,$(lib))))

$(foreach prog,  $(PROGRAMS),         $(eval $(call VARIABLE_template,$(prog))))
$(foreach prog,  $(PROGRAMS),         $(eval $(call PROGRAM_template,$(prog))))

mkdirs: $(DIRECTORIES)
