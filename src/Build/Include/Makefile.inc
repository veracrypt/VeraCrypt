#
# Derived from source code of TrueCrypt 7.1a, which is
# Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
# by the TrueCrypt License 3.0.
#
# Modifications and additions to the original source code (contained in this file)
# and all other portions of this file are Copyright (c) 2013-2017 AM Crypto
# and are governed by the Apache License 2.0 the full text of which is
# contained in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

$(NAME): $(NAME).a

clean:
	@echo Cleaning $(NAME)
	rm -f $(APPNAME) $(NAME).a $(OBJS) $(OBJSEX) $(OBJSNOOPT) $(OBJSHANI) $(OBJAESNI) $(OBJSSSE41) $(OBJSSSSE3) $(OBJSAVX2) $(OBJARMV8CRYPTO) $(OBJS:.o=.d) $(OBJSEX:.oo=.d) $(OBJSNOOPT:.o0=.d) $(OBJSHANI:.oshani=.d) $(OBJAESNI:.oaesni=.d) $(OBJSSSE41:.osse41=.d) $(OBJSSSSE3:.ossse3=.d) $(OBJSAVX2:.oavx2=.d) $(OBJARMV8CRYPTO:.oarmv8crypto=.d) *.gch

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

%.oaesni: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -mssse3 -msse4.1 -maes -c $< -o $@
	
%.ossse3: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -mssse3 -c $< -o $@

%.oavx2: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -mavx2 -c $< -o $@

%.oarmv8crypto: %.c
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -march=armv8-a+crypto -c $< -o $@

%.o: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -c $< -o $@

ifeq "$(PLATFORM)" "MacOSX"
%.o: %.mm
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -x objective-c++ -fblocks -c $< -o $@
endif

%.osse41: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -mssse3 -msse4.1 -c $< -o $@

%.oshani: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -mssse3 -msse4.1 -msha -c $< -o $@

%.oaesni: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -mssse3 -msse4.1 -maes -c $< -o $@
	
%.ossse3: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -mssse3 -c $< -o $@

%.oavx2: %.cpp
	@echo Compiling $(<F)
	$(CXX) $(CXXFLAGS) -mavx2 -c $< -o $@
	
%.o: %.S
	@echo Compiling $(<F)
	$(CC) $(CFLAGS) -c $< -o $@

ifeq "$(PLATFORM)" "MacOSX"
%.o: %.asm
	@echo Assembling $(<F)
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
OD_BIN := hexdump -v -e '1/1 "%u "'
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
-include $(OBJS:.o=.d) $(OBJSEX:.oo=.d) $(OBJSNOOPT:.o0=.d) $(OBJSHANI:.oshani=.d) $(OBJAESNI:.oaesni=.d) $(OBJSSSE41:.osse41=.d) $(OBJSSSSE3:.ossse3=.d) $(OBJSAVX2:.oavx2=.d) $(OBJARMV8CRYPTO:.oarmv8crypto=.d)


# Deterministic static library: the 'D' modifier zeroes member mtime/uid/gid
# and 'ranlib -D' writes a deterministic index. Both are probed functionally
# (running them on a throwaway archive) rather than by parsing --help, whose
# wording varies between binutils versions. Very old binutils that lack the
# feature simply falls back to a normal, still-correct archive.
# Probe also covers BSD ar / macOS libtool ar (neither supports -D): both
# variables come out empty there and the original ar/ranlib calls are used.
AR_DETERMINISTIC := $(shell t=$$(mktemp); rm -f $$t.a; $(AR) Drc $$t.a $$t >/dev/null 2>&1 && echo D; rm -f $$t $$t.a)
RANLIB_DETERMINISTIC := $(shell t=$$(mktemp); rm -f $$t.a; $(AR) rc $$t.a $$t >/dev/null 2>&1; $(RANLIB) -D $$t.a >/dev/null 2>&1 && echo -D; rm -f $$t $$t.a)

$(NAME).a: $(OBJS) $(OBJSEX) $(OBJSNOOPT) $(OBJSHANI) $(OBJAESNI) $(OBJSSSE41) $(OBJSSSSE3) $(OBJSAVX2) $(OBJARMV8CRYPTO)
	@echo Updating library $@
	rm -f $@
	$(AR) $(AFLAGS) $(AR_DETERMINISTIC)rc $@ $(OBJS) $(OBJSEX) $(OBJSNOOPT) $(OBJSHANI) $(OBJAESNI) $(OBJSSSE41) $(OBJSSSSE3) $(OBJSAVX2) $(OBJARMV8CRYPTO)
	$(RANLIB) $(RANLIB_DETERMINISTIC) $@
