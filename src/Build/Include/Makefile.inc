#
# Copyright (c) 2008 TrueCrypt Developers Association. All rights reserved.
#
# Governed by the TrueCrypt License 3.0 the full text of which is contained in
# the file License.txt included in TrueCrypt binary and source code distribution
# packages.
#

$(NAME): $(NAME).a

clean:
	@echo Cleaning $(NAME)
	rm -f $(APPNAME) $(NAME).a $(OBJS) $(OBJSEX) $(OBJS:.o=.d) *.gch

%.o: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -c $< -o $@

ifeq "$(PLATFORM)" "MacOSX"
%.o: %.asm
	@echo Assembling $(<F)
	$(AS) $(ASFLAGS) -f macho32 -o $@.32 $<
	$(AS) $(ASFLAGS) -f macho64 -o $@.64 $<
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
OD_BIN := od -v -t u1 -A n
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
-include $(OBJS:.o=.d) $(OBJSEX:.oo=.d)


$(NAME).a: $(OBJS) $(OBJSEX)
	@echo Updating library $@
	$(AR) $(AFLAGS) -rcu $@ $(OBJS) $(OBJSEX)
	$(RANLIB) $@
