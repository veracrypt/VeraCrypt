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
# SSSE3:		Enable SSSE3 support in compiler
# SSE41:		Enable SSE4.1 support in compiler

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
export AS := yasm
export RANLIB ?= ranlib

export CFLAGS := -Wall
export CXXFLAGS := -Wall -Wno-unused-parameter
C_CXX_FLAGS := -MMD -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGE_FILES -I$(BASE_DIR) -I$(BASE_DIR)/Crypto
export ASFLAGS := -D __GNUC__ -D __YASM__
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
	export VC_WX_STATIC := 1
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
export PLATFORM_ARCH := "Unknown"
export PLATFORM_UNSUPPORTED := 0

export CPU_ARCH ?= unknown
export SIMD_SUPPORTED := 0

ARCH = $(shell uname -m)

ifneq (,$(filter i386 i486 i586 i686 x86,$(ARCH)))
	CPU_ARCH = x86
    ASFLAGS += -f elf32 -D __BITS__=32
else ifneq (,$(filter x86_64 x86-64 amd64 x64,$(ARCH)))
	CPU_ARCH = x64
    ASFLAGS += -f elf64 -D __BITS__=64
else ifneq (,$(filter armv7l,$(ARCH)))
	PLATFORM_ARCH := armv7
	CPU_ARCH = armv7
endif

ifeq "$(origin NOASM)" "command line"
	CPU_ARCH = unknown
endif

ifeq "$(CPU_ARCH)" "x86"
	PLATFORM_ARCH := i386
	SIMD_SUPPORTED := 1
	C_CXX_FLAGS += -D TC_ARCH_X86
else ifeq "$(CPU_ARCH)" "x64"
	PLATFORM_ARCH := amd64
	SIMD_SUPPORTED := 1
	C_CXX_FLAGS += -D TC_ARCH_X64
endif


#------ Linux configuration ------

ifeq "$(shell uname -s)" "Linux"

	PLATFORM := Linux
	C_CXX_FLAGS += -DTC_UNIX -DTC_LINUX
	
	ifeq "$(SIMD_SUPPORTED)" "1"
		CFLAGS += -msse2
		CXXFLAGS += -msse2

		GCC_GTEQ_440 := $(shell expr `gcc -dumpversion | sed -e 's/\.\([0-9][0-9]\)/\1/g' -e 's/\.\([0-9]\)/0\1/g' -e 's/^[0-9]\{3,4\}$$/&00/'` \>= 40400)
		GCC_GTEQ_430 := $(shell expr `gcc -dumpversion | sed -e 's/\.\([0-9][0-9]\)/\1/g' -e 's/\.\([0-9]\)/0\1/g' -e 's/^[0-9]\{3,4\}$$/&00/'` \>= 40300)
		ifeq "$(GCC_GTEQ_440)" "1"
			CFLAGS += -maes
			CXXFLAGS += -maes
		endif

		ifeq "$(GCC_GTEQ_430)" "1"
			ifeq "$(origin SSSE3)" "command line"
				CFLAGS += -mssse3
				CXXFLAGS += -mssse3
			endif

			ifeq "$(origin SSE41)" "command line"
				CFLAGS += -mssse3 -msse4.1
				CXXFLAGS += -mssse3 -msse4.1
			endif
		endif
	endif

	ifeq "$(TC_BUILD_CONFIG)" "Release"
		C_CXX_FLAGS += -fdata-sections -ffunction-sections -fpie
		LFLAGS += -Wl,--gc-sections -pie

		ifneq "$(shell ld --help 2>&1 | grep sysv | wc -l)" "0"
			LFLAGS += -Wl,--hash-style=sysv
		endif

		WXCONFIG_CFLAGS += -fdata-sections -ffunction-sections -fpie
		WXCONFIG_CXXFLAGS += -fdata-sections -ffunction-sections -fpie
	endif

	ifneq "$(origin WXSTATIC)" "command line"
		LFLAGS += -ldl
	else
		GCC5USED := $(shell expr `gcc -dumpversion | cut -f1 -d.` \>= 5)
		ifeq "$(GCC5USED)" "1"
			CXXFLAGS += -D_GLIBCXX_USE_CXX11_ABI=0
			WXCONFIG_CXXFLAGS += -D_GLIBCXX_USE_CXX11_ABI=0
		endif
	endif

endif

#------ Mac OS X configuration ------

ifeq "$(shell uname -s)" "Darwin"

	PLATFORM := MacOSX
	APPNAME := VeraCrypt

	export VC_OSX_TARGET ?= 10.7

	#check to see if XCode 3 path exists.Otherwise, use XCode 4 path
	VC_OSX_SDK  := /Developer/SDKs/MacOSX$(VC_OSX_TARGET).sdk
	ifeq ($(wildcard $(VC_OSX_SDK)/SDKSettings.plist),)
		VC_OSX_SDK := /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX$(VC_OSX_TARGET).sdk
	endif

	CC := gcc
	CXX := g++

	C_CXX_FLAGS += -DTC_UNIX -DTC_BSD -DTC_MACOSX -mmacosx-version-min=$(VC_OSX_TARGET) -isysroot $(VC_OSX_SDK)
	LFLAGS += -mmacosx-version-min=$(VC_OSX_TARGET) -Wl,-syslibroot $(VC_OSX_SDK)
	WX_CONFIGURE_FLAGS += --with-macosx-version-min=$(VC_OSX_TARGET) --with-macosx-sdk=$(VC_OSX_SDK)

	ifeq "$(CPU_ARCH)" "x64"
		CPU_ARCH = x86
	endif

	CFLAGS += -msse2
	CXXFLAGS += -msse2

	ifeq "$(origin SSSE3)" "command line"
		CFLAGS += -mssse3
		CXXFLAGS += -mssse3
	endif

	ifeq "$(origin SSE41)" "command line"
		CFLAGS += -mssse3 -msse4.1
		CXXFLAGS += -mssse3 -msse4.1
	endif

	AS := $(BASE_DIR)/Build/Tools/MacOSX/yasm
	export ASFLAGS32 := -D __GNUC__ -D __YASM__ -D __BITS__=32 --prefix=_ -f macho32
	export ASFLAGS64 := -D __GNUC__ -D __YASM__ -D __BITS__=64 --prefix=_ -f macho64

	ifeq "$(TC_BUILD_CONFIG)" "Release"

		export DISABLE_PRECOMPILED_HEADERS := 1

		S := $(C_CXX_FLAGS)
		C_CXX_FLAGS = $(subst -MMD,,$(S))

		C_CXX_FLAGS += -gfull -arch i386 -arch x86_64
		LFLAGS += -Wl,-dead_strip -arch i386 -arch x86_64

		WX_CONFIGURE_FLAGS += --enable-universal_binary=i386,x86_64
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
	
	CC := cc
	CXX := c++
	
	ifeq "$(TC_BUILD_CONFIG)" "Release"
		C_CXX_FLAGS += -fdata-sections -ffunction-sections -fpie
		LFLAGS += -Wl,--gc-sections -pie

		ifneq "$(shell ld --help 2>&1 | grep sysv | wc -l)" "0"
			LFLAGS += -Wl,--hash-style=sysv
		endif

		WXCONFIG_CFLAGS += -fpie -fPIC
		WXCONFIG_CXXFLAGS += -fpie -fPIC
	endif

	ifeq "$(SIMD_SUPPORTED)" "1"
		CFLAGS += -msse2 -maes
		CXXFLAGS += -msse2 -maes

		ifeq "$(origin SSSE3)" "command line"
			CFLAGS += -mssse3
			CXXFLAGS += -mssse3
		endif

		ifeq "$(origin SSE41)" "command line"
			CFLAGS += -mssse3 -msse4.1
			CXXFLAGS += -mssse3 -msse4.1
		endif
	endif

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
LFLAGS := $(LFLAGS) $(TC_EXTRA_LFLAGS)

WX_CONFIGURE_FLAGS += --enable-unicode -disable-shared --disable-dependency-tracking --disable-compat26 --enable-exceptions --enable-std_string --enable-dataobj --enable-mimetype \
	--disable-protocol --disable-protocols --disable-url --disable-ipc --disable-sockets --disable-fs_inet --disable-ole --disable-docview --disable-clipboard \
	--disable-help --disable-html --disable-mshtmlhelp --disable-htmlhelp --disable-mdi --disable-metafile --disable-webkit --disable-webview \
	--disable-xrc --disable-aui --disable-postscript --disable-printarch \
	--disable-arcstream --disable-fs_archive --disable-fs_zip --disable-tarstream --disable-zipstream \
	--disable-animatectrl --disable-bmpcombobox --disable-calendar --disable-caret --disable-checklst --disable-collpane --disable-colourpicker --disable-comboctrl \
	--disable-datepick --disable-display --disable-dirpicker --disable-filepicker --disable-fontpicker --disable-grid  --disable-dataviewctrl \
	--disable-listbook --disable-odcombobox --disable-sash  --disable-searchctrl --disable-slider --disable-splitter --disable-togglebtn \
	--disable-toolbar --disable-tbarnative --disable-treebook --disable-toolbook --disable-tipwindow --disable-popupwin \
	--disable-commondlg --disable-aboutdlg --disable-coldlg --disable-finddlg --disable-fontdlg --disable-numberdlg --disable-splash \
	--disable-tipdlg --disable-progressdlg --disable-wizarddlg --disable-miniframe --disable-splines --disable-palette \
	--disable-richtext --disable-dialupman --disable-debugreport --disable-filesystem --disable-rearrangectrl --disable-treelist --disable-richmsgdlg \
	--disable-richtooltip --disable-propgrid --disable-stc --without-libnotify \
	--without-gtkprint --without-gnomevfs --disable-fsvolume --disable-fswatcher \
	--disable-graphics_ctx --disable-sound --disable-mediactrl --disable-joystick --disable-apple_ieee \
	--disable-gif --disable-pcx --disable-tga --disable-iff --disable-gif --disable-pnm --disable-svg \
	--without-expat --without-libtiff --without-libjpeg --without-libpng -without-regex --without-zlib

ifeq "$(PLATFORM)" "Linux"
WX_CONFIGURE_FLAGS += --disable-tooltips
endif

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

install:
	$(MAKE) -C Main -f Main.make NAME=Main install

package:
	$(MAKE) -C Main -f Main.make NAME=Main package

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
