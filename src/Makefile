#
# Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.
#
# Governed by the TrueCrypt License 3.0 the full text of which is contained in
# the file License.txt included in TrueCrypt binary and source code distribution
# packages.
#

#------ Command line arguments ------
# DEBUG:		Disable optimizations and enable debugging checks
# DEBUGGER:		Enable debugging information for use by debuggers
# NOASM:		Exclude modules requiring assembler
# NOGUI:		Disable graphical user interface (build console-only application)
# NOSTRIP:		Do not strip release binary
# NOTEST:		Do not test release binary
# RESOURCEDIR:	Run-time resource directory
# VERBOSE:		Enable verbose messages
# WXSTATIC:		Use static wxWidgets library

#------ Targets ------
# all
# clean
# wxbuild:		Configure and build wxWidgets - source code must be located at $(WX_ROOT)


#------ Build configuration ------

export APPNAME := veracrypt
export BASE_DIR := $(CURDIR)
export BUILD_INC := $(BASE_DIR)/Build/Include

export AR ?= ar
export CC ?= gcc
export CXX ?= g++
export AS := nasm
export RANLIB ?= ranlib

export CFLAGS := -Wall
export CXXFLAGS := -Wall -Wno-unused-parameter
C_CXX_FLAGS := -MMD -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES -I$(BASE_DIR) -I$(BASE_DIR)/Crypto
export ASFLAGS := -Ox -D __GNUC__
export LFLAGS :=

export PKG_CONFIG_PATH ?= /usr/local/lib/pkgconfig

export WX_CONFIG ?= wx-config
export WX_CONFIG_ARGS := --unicode
WX_CONFIGURE_FLAGS :=
export WXCONFIG_CFLAGS :=
export WXCONFIG_CXXFLAGS :=
WX_ROOT ?= ..


export TC_BUILD_CONFIG := Release

ifeq "$(origin DEBUG)" "command line"
	ifneq "$(DEBUG)" "0"
		TC_BUILD_CONFIG := Debug
	endif
endif

ifeq "$(origin NOGUI)" "command line"
	export TC_NO_GUI := 1
	C_CXX_FLAGS += -DTC_NO_GUI
	WX_CONFIGURE_FLAGS += --disable-gui
endif

ifdef PKCS11_INC
	C_CXX_FLAGS += -I$(PKCS11_INC)
else
	C_CXX_FLAGS += -I$(CURDIR)/PKCS11
endif

ifeq "$(origin RESOURCEDIR)" "command line"
	C_CXX_FLAGS += -DTC_RESOURCE_DIR="$(RESOURCEDIR)"
endif

ifneq "$(origin VERBOSE)" "command line"
	MAKEFLAGS += -s
endif

ifeq "$(origin WXSTATIC)" "command line"
	WX_CONFIG = $(WX_BUILD_DIR)/wx-config
	WX_CONFIG_ARGS += --static
endif


#------ Release configuration ------

ifeq "$(TC_BUILD_CONFIG)" "Release"

	C_CXX_FLAGS += -O2 -fno-strict-aliasing  # Do not enable strict aliasing
	export WX_BUILD_DIR ?= $(BASE_DIR)/wxrelease
	WX_CONFIGURE_FLAGS += --disable-debug_flag --disable-debug_gdb --disable-debug_info

else

#------ Debug configuration ------

	C_CXX_FLAGS += -DDEBUG
	CXXFLAGS += -fno-default-inline -Wno-unused-function -Wno-unused-variable
	export WX_BUILD_DIR ?= $(BASE_DIR)/wxdebug
	WX_CONFIGURE_FLAGS += --enable-debug_flag --disable-debug_gdb --disable-debug_info

endif


#------ Debugger configuration ------

ifeq "$(origin DEBUGGER)" "command line"

	C_CXX_FLAGS += -ggdb  
	WX_CONFIGURE_FLAGS += --enable-debug_gdb --enable-debug_info

endif


#------ Platform configuration ------

export PLATFORM := "Unknown"
export PLATFORM_UNSUPPORTED := 0

export CPU_ARCH ?= unknown

ARCH = $(shell uname -p)
ifeq "$(ARCH)" "unknown"
	ARCH = $(shell uname -m)
endif

ifneq (,$(filter i386 i486 i586 i686 x86,$(ARCH)))
	CPU_ARCH = x86
	ASM_OBJ_FORMAT = elf32
else ifneq (,$(filter x86_64 x86-64 amd64 x64,$(ARCH)))
	CPU_ARCH = x64
	ASM_OBJ_FORMAT = elf64
endif

ifeq "$(origin NOASM)" "command line"
	CPU_ARCH = unknown
endif

ifeq "$(CPU_ARCH)" "x86"
	C_CXX_FLAGS += -D TC_ARCH_X86
else ifeq "$(CPU_ARCH)" "x64"
	C_CXX_FLAGS += -D TC_ARCH_X64
endif


#------ Linux configuration ------

ifeq "$(shell uname -s)" "Linux"

	PLATFORM := Linux
	C_CXX_FLAGS += -DTC_UNIX -DTC_LINUX

	ifeq "$(TC_BUILD_CONFIG)" "Release"
		C_CXX_FLAGS += -fdata-sections -ffunction-sections
		LFLAGS += -Wl,--gc-sections

		ifneq "$(shell ld --help 2>&1 | grep sysv | wc -l)" "0"
			LFLAGS += -Wl,--hash-style=sysv
		endif

		WXCONFIG_CFLAGS += -fdata-sections -ffunction-sections
		WXCONFIG_CXXFLAGS += -fdata-sections -ffunction-sections
	endif

endif


#------ Mac OS X configuration ------

ifeq "$(shell uname -s)" "Darwin"

	PLATFORM := MacOSX
	APPNAME := VeraCrypt

	TC_OSX_SDK ?= /Developer/SDKs/MacOSX10.4u.sdk
	CC := gcc-4.0
	CXX := g++-4.0

	C_CXX_FLAGS += -DTC_UNIX -DTC_BSD -DTC_MACOSX -mmacosx-version-min=10.4 -isysroot $(TC_OSX_SDK)
	LFLAGS += -mmacosx-version-min=10.4 -Wl,-syslibroot $(TC_OSX_SDK)
	WX_CONFIGURE_FLAGS += --with-macosx-version-min=10.4 --with-macosx-sdk=$(TC_OSX_SDK)

	ifeq "$(CPU_ARCH)" "x64"
		CPU_ARCH = x86
	endif

	ASM_OBJ_FORMAT = macho
	ASFLAGS += --prefix _

	ifeq "$(TC_BUILD_CONFIG)" "Release"

		export DISABLE_PRECOMPILED_HEADERS := 1

		S := $(C_CXX_FLAGS)
		C_CXX_FLAGS = $(subst -MMD,,$(S))

		C_CXX_FLAGS += -gfull -arch i386 -arch ppc
		LFLAGS += -Wl,-dead_strip -arch i386 -arch ppc

		WX_CONFIGURE_FLAGS += --enable-universal_binary
		WXCONFIG_CFLAGS += -gfull
		WXCONFIG_CXXFLAGS += -gfull

	else

		WX_CONFIGURE_FLAGS += --disable-universal_binary

	endif

endif


#------ FreeBSD configuration ------

ifeq "$(shell uname -s)" "FreeBSD"

	PLATFORM := FreeBSD
	PLATFORM_UNSUPPORTED := 1
	C_CXX_FLAGS += -DTC_UNIX -DTC_BSD -DTC_FREEBSD

endif


#------ Solaris configuration ------

ifeq "$(shell uname -s)" "SunOS"

	PLATFORM := Solaris
	PLATFORM_UNSUPPORTED := 1
	C_CXX_FLAGS += -DTC_UNIX -DTC_SOLARIS
	WX_CONFIGURE_FLAGS += --with-gtk

endif


#------ Common configuration ------

CFLAGS := $(C_CXX_FLAGS) $(CFLAGS) $(TC_EXTRA_CFLAGS)
CXXFLAGS := $(C_CXX_FLAGS) $(CXXFLAGS) $(TC_EXTRA_CXXFLAGS)
ASFLAGS += -f $(ASM_OBJ_FORMAT)
LFLAGS := $(LFLAGS) $(TC_EXTRA_LFLAGS)

WX_CONFIGURE_FLAGS += --enable-unicode -disable-shared --disable-dependency-tracking --disable-compat26 --enable-exceptions --enable-std_string --enable-dataobj --enable-mimetype \
	--disable-protocol --disable-protocols --disable-url --disable-ipc --disable-sockets --disable-fs_inet --disable-ole --disable-docview --disable-clipboard \
	--disable-help --disable-html --disable-mshtmlhelp --disable-htmlhelp --disable-mdi --disable-metafile --disable-webkit \
	--disable-xrc --disable-aui --disable-postscript --disable-printarch \
	--disable-arcstream --disable-fs_archive --disable-fs_zip --disable-tarstream --disable-zipstream \
	--disable-animatectrl --disable-bmpcombobox --disable-calendar --disable-caret --disable-checklst --disable-collpane --disable-colourpicker --disable-comboctrl \
	--disable-datepick --disable-display --disable-dirpicker --disable-filepicker --disable-fontpicker --disable-grid  --disable-dataviewctrl \
	--disable-listbook --disable-odcombobox --disable-sash  --disable-searchctrl --disable-slider --disable-splitter --disable-togglebtn \
	--disable-toolbar --disable-tbarnative --disable-treebook --disable-toolbook --disable-tipwindow --disable-popupwin \
	--disable-commondlg --disable-aboutdlg --disable-coldlg --disable-finddlg --disable-fontdlg --disable-numberdlg --disable-splash \
	--disable-tipdlg --disable-progressdlg --disable-wizarddlg --disable-miniframe --disable-tooltips --disable-splines --disable-palette \
	--disable-richtext --disable-dialupman --disable-debugreport --disable-filesystem --disable-rearrangectrl --disable-treelist --disable-richmsgdlg \
	--disable-richtooltip --disable-propgrid --disable-stc --without-libnotify \
	--without-gtkprint --without-gnomevfs --disable-fsvolume --disable-fswatcher \
	--disable-graphics_ctx --disable-sound --disable-mediactrl --disable-joystick --disable-apple_ieee \
	--disable-gif --disable-pcx --disable-tga --disable-iff --disable-gif --disable-pnm --disable-svg \
	--without-expat --without-libtiff --without-libjpeg --without-libpng -without-regex --without-zlib


#------ Project build ------

PROJ_DIRS := Platform Volume Driver/Fuse Core Main

.PHONY: all clean wxbuild

all clean:
	@if pwd | grep -q ' '; then echo 'Error: source code is stored in a path containing spaces' >&2; exit 1; fi

	@for DIR in $(PROJ_DIRS); do \
		PROJ=$$(echo $$DIR | cut -d/ -f1); \
		$(MAKE) -C $$DIR -f $$PROJ.make NAME=$$PROJ $(MAKECMDGOALS) || exit $?; \
		export LIBS="$(BASE_DIR)/$$DIR/$$PROJ.a $$LIBS"; \
	done	


#------ wxWidgets build ------

ifeq "$(MAKECMDGOALS)" "wxbuild"
CFLAGS :=
CXXFLAGS :=
LFLAGS :=
endif

wxbuild:

ifneq "$(shell test -f $(WX_ROOT)/configure || test -f $(WX_BUILD_DIR)/../configure && echo 1)" "1"
	@echo 'Error: WX_ROOT must point to wxWidgets source code directory' >&2
	@exit 1
endif

	rm -rf "$(WX_BUILD_DIR)"
	mkdir -p "$(WX_BUILD_DIR)"
	@echo Configuring wxWidgets library...
	cd "$(WX_BUILD_DIR)" && "$(WX_ROOT)/configure" $(WX_CONFIGURE_FLAGS) >/dev/null
	
	@echo Building wxWidgets library...
	cd "$(WX_BUILD_DIR)" && $(MAKE)
