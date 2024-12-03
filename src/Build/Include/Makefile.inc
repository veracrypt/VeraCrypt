#
# Derived from source code of TrueCrypt 7.1a, which is
# Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
# by the TrueCrypt License 3.0.
#
# Modifications and additions to the original source code (contained in this file)
# and all other portions of this file are Copyright (c) 2013-2017 IDRIX
# and are governed by the Apache License 2.0 the full text of which is
# contained in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

.PHONY: test-only lib $(NAME)

ifeq "$(OBJS)" ""
$(NAME): test-only
else
$(NAME): lib
endif

test-only: $(NAME)Testing $(NAME)Test.a
lib: $(NAME).a $(NAME)Test.a $(NAME)Testing

clean:
	@echo Cleaning $(NAME)
	rm -f $(APPNAME) $(NAME).a $(OBJS) $(OBJSEX) $(OBJSNOOPT) $(OBJSHANI) $(OBJSSSE41) $(OBJSSSSE3) $(OBJS:.o=.d) $(OBJSEX:.oo=.d) $(OBJSNOOPT:.o0=.d) $(OBJSHANI:.oshani=.d) $(OBJSSSE41:.osse41=.d) $(OBJSSSSE3:.ossse3=.d) *.gch
	rm -f $(NAME)Testing.a $(NAME)Test.a $(TEST_OBJS)

%.o: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -c $< -o $@

%.o0: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -O0 -c $< -o $@
	
%.osse41: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -mssse3 -msse4.1 -c $< -o $@

%.oshani: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -mssse3 -msse4.1 -msha -c $< -o $@
	
%.ossse3: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -mssse3 -c $< -o $@

%Test.o: %Test.cpp
	@echo Compiling test $(<F)
	$(CXX) $(CXXFLAGS) -I$(BASE_DIR)/Testing -c $< -o $@

%.o: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -c $< -o $@
	
%.osse41: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -mssse3 -msse4.1 -c $< -o $@

%.oshani: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -mssse3 -msse4.1 -msha -c $< -o $@
	
%.ossse3: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -mssse3 -c $< -o $@
	
%.o: %.S
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -c $< -o $@

ifeq "$(PLATFORM)" "MacOSX"
%.o: %.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS32) -f macho32 -o $@.32 $<
	$(AS) $(ASFLAGS64) -f macho64 -o $@.64 $<
	$(AS) $(ASFLAGS32) -f macho32 -o $@.32 $<
	$(AS) $(ASFLAGS64) -f macho64 -o $@.64 $<
	lipo -create $@.32 $@.64 -output $@
else
%.o: %.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS) -o $@ $<
endif

# Precompiled headers
%.h.gch: %.h
	@echo Precompiling $(<F)
	$(CXX) $(CXXFLAGS) -g0 -c $< || (rm -f $(<F).gch && exit 1)


# Embedded files
ifeq "$(PLATFORM)" "OpenBSD"
OD_BIN := ggod -v -t u1 -A n
else
OD_BIN := od -v -t u1 -A n
endif
TR_SED_BIN := tr '\n' ' ' | tr -s ' ' ',' | sed -e 's/^,//g' -e 's/,$$/n/' | tr 'n' '\n'

%.xml.h: %.xml
	@echo Converting $(<F)
	$(OD_BIN) $< | $(TR_SED_BIN) >$@

%.txt.h: %.txt
	@echo Converting $(<F)
	$(OD_BIN) $< | $(TR_SED_BIN) >$@

%.bmp.h: %.bmp
	@echo Converting $(<F)
	$(OD_BIN) $< | $(TR_SED_BIN) >$@


# Dependencies
-include $(OBJS:.o=.d) $(OBJSEX:.oo=.d) $(OBJSNOOPT:.o0=.d) $(OBJSHANI:.oshani=.d) $(OBJSSSE41:.osse41=.d) $(OBJSSSSE3:.ossse3=.d)


$(NAME).a: $(OBJS) $(OBJSEX) $(OBJSNOOPT) $(OBJSHANI) $(OBJSSSE41) $(OBJSSSSE3)
ifneq "$(OBJS)" ""
	@echo Updating library $@
	$(AR) $(AFLAGS) -rcu $@ $(OBJS) $(OBJSEX) $(OBJSNOOPT) $(OBJSHANI) $(OBJSSSE41) $(OBJSSSSE3)
	$(RANLIB) $@
endif

$(NAME)Test.a: $(TEST_OBJS)
ifneq "$(TEST_OBJS)" ""
	@echo Updating test library $@
	$(AR) $(AFLAGS) -rcu $@ $(TEST_OBJS)
	$(RANLIB) $@
endif

$(NAME)Testing: $(TEST_EXECS) $(OBJS) $(OBJSEX) $(OBJSNOOPT) $(LIBS) $(TEST_LIBS) $(TEST_OBJS)
ifneq "$(TEST_EXECS)" ""
	@for TE in $(TEST_EXECS); do \
			export EXEC_NAME=`basename "$$TE" .o`; \
			echo Compiling $${EXEC_NAME}Run; \
			$(CXX) -o $${EXEC_NAME}Run $${TE} $(TEST_LIBS) $(TEST_OBJS) $(OBJS) $(LIBS) $(TEST_EXT_LIBS) $(LFLAGS) $(TEST_LFLAGS); \
	done
endif