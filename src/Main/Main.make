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

OBJS :=
OBJS += Application.o
OBJS += CommandLineInterface.o
OBJS += FavoriteVolume.o
OBJS += LanguageStrings.o
OBJS += StringFormatter.o
OBJS += TextUserInterface.o
OBJS += UserInterface.o
OBJS += UserPreferences.o
OBJS += Xml.o
OBJS += Unix/Main.o
OBJS += Resources.o

ifndef TC_NO_GUI
OBJS += FatalErrorHandler.o
OBJS += GraphicUserInterface.o
ifeq "$(PLATFORM)" "MacOSX"
OBJS += MacOSXSecureTextFieldHotkeys.o
endif
OBJS += VolumeHistory.o
OBJS += Forms/AboutDialog.o
OBJS += Forms/BenchmarkDialog.o
OBJS += Forms/ChangePasswordDialog.o
OBJS += Forms/DeviceSelectionDialog.o
OBJS += Forms/EncryptionOptionsWizardPage.o
OBJS += Forms/EncryptionTestDialog.o
OBJS += Forms/FavoriteVolumesDialog.o
OBJS += Forms/Forms.o
OBJS += Forms/InfoWizardPage.o
OBJS += Forms/KeyfileGeneratorDialog.o
OBJS += Forms/KeyfilesDialog.o
OBJS += Forms/KeyfilesPanel.o
OBJS += Forms/LegalNoticesDialog.o
OBJS += Forms/MainFrame.o
OBJS += Forms/MountOptionsDialog.o
OBJS += Forms/NewSecurityTokenKeyfileDialog.o
OBJS += Forms/PreferencesDialog.o
OBJS += Forms/ProgressWizardPage.o
OBJS += Forms/RandomPoolEnrichmentDialog.o
OBJS += Forms/SecurityTokenKeyfilesDialog.o
OBJS += Forms/SelectDirectoryWizardPage.o
OBJS += Forms/VolumePasswordPanel.o
OBJS += Forms/VolumePropertiesDialog.o
OBJS += Forms/VolumeCreationProgressWizardPage.o
OBJS += Forms/VolumeCreationWizard.o
OBJS += Forms/VolumeFormatOptionsWizardPage.o
OBJS += Forms/VolumeLocationWizardPage.o
OBJS += Forms/VolumePasswordWizardPage.o
OBJS += Forms/VolumePimWizardPage.o
OBJS += Forms/VolumeSizeWizardPage.o
OBJS += Forms/WaitDialog.o
OBJS += Forms/WizardFrame.o
endif

ifndef DISABLE_PRECOMPILED_HEADERS
PCH := SystemPrecompiled.h.gch
endif

RESOURCES :=
RESOURCES += ../License.txt.h
RESOURCES += ../Common/Language.xml.h
ifndef TC_NO_GUI
RESOURCES += ../Common/Textual_logo_96dpi.bmp.h
RESOURCES += ../Format/VeraCrypt_Wizard.bmp.h
RESOURCES += ../Mount/Drive_icon_96dpi.bmp.h
RESOURCES += ../Mount/Drive_icon_mask_96dpi.bmp.h
RESOURCES += ../Mount/Logo_96dpi.bmp.h
endif

CXXFLAGS += -I$(BASE_DIR)/Main


#------ wxWidgets configuration ------

ifdef TC_NO_GUI
WX_CONFIG_LIBS := base
else
WX_CONFIG_LIBS := adv,core,base
endif

ifeq "$(TC_BUILD_CONFIG)" "Release"

CXXFLAGS += $(shell $(WX_CONFIG) $(WX_CONFIG_ARGS) --cxxflags)
WX_LIBS = $(shell $(WX_CONFIG) $(WX_CONFIG_ARGS) --libs $(WX_CONFIG_LIBS))

else

CXXFLAGS += $(shell $(WX_CONFIG) --debug $(WX_CONFIG_ARGS) --cxxflags)
WX_LIBS = $(shell $(WX_CONFIG) --debug $(WX_CONFIG_ARGS) --libs $(WX_CONFIG_LIBS))

endif


#------ FUSE configuration ------

FUSE_LIBS = $(shell $(PKG_CONFIG) $(VC_FUSE_PACKAGE) --libs)

#------ Executable ------

HASH_CHAR := \#
export TC_VERSION := $(shell awk -F '"' '/^[[:space:]]*$(HASH_CHAR)define[[:space:]]+VERSION_STRING[[:space:]]*"/ { print $$2; exit }' ../Common/Tcdefs.h)

#------ Linux package naming ------
ifeq "$(PLATFORM)" "Linux"

ifdef TC_NO_GUI
INSTALLER_TYPE := console
ifeq "$(origin NOSSE2)" "command line"
PACKAGE_NAME := $(APPNAME)_$(TC_VERSION)_console_$(PLATFORM_ARCH)_legacy.tar.gz
else
PACKAGE_NAME := $(APPNAME)_$(TC_VERSION)_console_$(PLATFORM_ARCH).tar.gz
endif
else
INSTALLER_TYPE := gui
ifeq "$(origin NOSSE2)" "command line"
PACKAGE_NAME := $(APPNAME)_$(TC_VERSION)_$(PLATFORM_ARCH)_legacy.tar.gz
else
PACKAGE_NAME := $(APPNAME)_$(TC_VERSION)_$(PLATFORM_ARCH).tar.gz
endif
endif

# Determine GUI/GTK conditions
GUI_CONDITION := $(filter gui,$(INSTALLER_TYPE))
GTK2_CONDITION := $(filter 2,$(GTK_VERSION))

ifeq "$(origin NOSSE2)" "command line"
INTERNAL_INSTALLER_NAME := veracrypt_install_$(INSTALLER_TYPE)_$(CPU_ARCH)_legacy.sh

ifneq (,$(GUI_CONDITION))
ifneq (,$(GTK2_CONDITION))
INSTALLER_NAME := veracrypt-$(TC_VERSION)-setup-gtk2-gui-$(CPU_ARCH)-legacy
else
INSTALLER_NAME := veracrypt-$(TC_VERSION)-setup-$(INSTALLER_TYPE)-$(CPU_ARCH)-legacy
endif
else
INSTALLER_NAME := veracrypt-$(TC_VERSION)-setup-$(INSTALLER_TYPE)-$(CPU_ARCH)-legacy
endif

else
INTERNAL_INSTALLER_NAME := veracrypt_install_$(INSTALLER_TYPE)_$(CPU_ARCH).sh

ifneq (,$(GUI_CONDITION))
ifneq (,$(GTK2_CONDITION))
INSTALLER_NAME := veracrypt-$(TC_VERSION)-setup-gtk2-gui-$(CPU_ARCH)
else
INSTALLER_NAME := veracrypt-$(TC_VERSION)-setup-$(INSTALLER_TYPE)-$(CPU_ARCH)
endif
else
INSTALLER_NAME := veracrypt-$(TC_VERSION)-setup-$(INSTALLER_TYPE)-$(CPU_ARCH)
endif

endif

endif
#-----------------------------------

#------ FreeBSD package naming ------
ifeq "$(PLATFORM)" "FreeBSD"

SYSTEMNAME = $(shell uname -n)

ifdef TC_NO_GUI
INSTALLER_TYPE := console
PACKAGE_NAME := $(APPNAME)_$(TC_VERSION)_$(SYSTEMNAME)_console_$(PLATFORM_ARCH).tar.gz
else
INSTALLER_TYPE := gui
PACKAGE_NAME := $(APPNAME)_$(TC_VERSION)_$(SYSTEMNAME)_$(PLATFORM_ARCH).tar.gz
endif

# Determine GUI/GTK conditions
GUI_CONDITION := $(filter gui,$(INSTALLER_TYPE))
GTK2_CONDITION := $(filter 2,$(GTK_VERSION))

INTERNAL_INSTALLER_NAME := veracrypt_install_$(SYSTEMNAME)_$(INSTALLER_TYPE)_$(CPU_ARCH).sh

ifneq (,$(GUI_CONDITION))
ifneq (,$(GTK2_CONDITION))
INSTALLER_NAME := veracrypt-$(TC_VERSION)-$(SYSTEMNAME)-setup-gtk2-gui-$(CPU_ARCH)
else
INSTALLER_NAME := veracrypt-$(TC_VERSION)-$(SYSTEMNAME)-setup-$(INSTALLER_TYPE)-$(CPU_ARCH)
endif
else
INSTALLER_NAME := veracrypt-$(TC_VERSION)-$(SYSTEMNAME)-setup-$(INSTALLER_TYPE)-$(CPU_ARCH)
endif

endif
#-----------------------------------

# Probe strip --enable-deterministic-archives against a private object
# rather than "-V" (which can fail in getopt before printing). All
# platforms, so non-Linux behaviour matches the original PR.
STRIP_DETERMINISTIC := $(strip $(shell d=$$(mktemp -d 2>/dev/null) && printf 'int x;\n' | $(CC) -x c -c - -o "$$d/o.o" >/dev/null 2>&1 && strip --enable-deterministic-archives "$$d/o.o" >/dev/null 2>&1 && echo --enable-deterministic-archives; rm -rf "$$d"))

$(APPNAME): $(LIBS) $(OBJS)
	@echo Linking $@
	$(CXX) -o $(APPNAME) $(OBJS) $(LIBS) $(AYATANA_LIBS) $(FUSE_LIBS) $(WX_LIBS) $(LFLAGS)

ifeq "$(TC_BUILD_CONFIG)" "Release"
ifndef NOSTRIP
	strip $(STRIP_DETERMINISTIC) $(APPNAME)
endif

ifndef NOTEST
	./$(APPNAME) --text --test >/dev/null || exit 1
endif

ifeq "$(PLATFORM_UNSUPPORTED)" "1"
	@echo; echo "WARNING: This platform may be unsupported. To avoid possible serious problems, please read the chapter pertaining to $(PLATFORM) in Readme.txt."; echo
endif
endif

ifeq "$(PLATFORM)" "MacOSX"
prepare: $(APPNAME)
	mkdir -p $(APPNAME).app/Contents/MacOS $(APPNAME).app/Contents/Resources/doc
	rm -rf $(APPNAME).app/Contents/Resources/doc/HTML
	mkdir -p $(APPNAME).app/Contents/Resources/doc/HTML
	mkdir -p $(APPNAME).app/Contents/MacOS $(APPNAME).app/Contents/Resources/languages
	-rm -f $(APPNAME).app/Contents/MacOS/$(APPNAME)
	-rm -f $(APPNAME).app/Contents/MacOS/$(APPNAME)_console

ifeq "$(TC_BUILD_CONFIG)" "Release"
ifdef TC_NO_GUI
	cp $(BASE_DIR)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)_console
else
	cp $(BASE_DIR)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)
endif
else
ifdef TC_NO_GUI
	-rm -f $(BASE_DIR)/Main/$(APPNAME)_console
	cp $(BASE_DIR)/Main/$(APPNAME) $(BASE_DIR)/Main/$(APPNAME)_console
	-ln -sf $(BASE_DIR)/Main/$(APPNAME)_console $(APPNAME).app/Contents/MacOS/$(APPNAME)_console
else
	-ln -sf $(BASE_DIR)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)
endif
endif

	cp $(BASE_DIR)/Resources/Icons/VeraCrypt.icns $(APPNAME).app/Contents/Resources
	cp $(BASE_DIR)/Resources/Icons/VeraCrypt_Volume.icns $(APPNAME).app/Contents/Resources
	cp -R $(BASE_DIR)/../doc/html/* $(APPNAME).app/Contents/Resources/doc/HTML
	cp $(BASE_DIR)/../Translations/* $(APPNAME).app/Contents/Resources/languages

	echo -n APPLTRUE >$(APPNAME).app/Contents/PkgInfo
ifdef VC_LEGACY_BUILD
	sed -e 's/_VERSION_/$(patsubst %a,%.1,$(patsubst %b,%.2,$(TC_VERSION)))/' ../Build/Resources/MacOSX/Info.plist.legacy.xml >$(APPNAME).app/Contents/Info.plist
else
	sed -e 's/_VERSION_/$(patsubst %a,%.1,$(patsubst %b,%.2,$(TC_VERSION)))/' ../Build/Resources/MacOSX/Info.plist.xml >$(APPNAME).app/Contents/Info.plist
endif
	chmod -R go-w $(APPNAME).app
ifneq ("$(LOCAL_DEVELOPMENT_BUILD)","true")
	codesign -s "Developer ID Application: IDRIX (Z933746L2S)" --timestamp $(APPNAME).app
endif

install: prepare
	cp -R $(APPNAME).app /Applications/.

package: prepare
ifdef VC_LEGACY_BUILD
	/usr/local/bin/packagesbuild $(BASE_DIR)/Setup/MacOSX/veracrypt_Legacy.pkgproj
	productsign --sign "Developer ID Installer: IDRIX (Z933746L2S)" --timestamp "$(BASE_DIR)/Setup/MacOSX/VeraCrypt Legacy $(TC_VERSION).pkg" $(BASE_DIR)/Setup/MacOSX/VeraCrypt_$(TC_VERSION).pkg
	rm -f $(APPNAME)_Legacy_$(TC_VERSION).dmg
else
ifeq "$(VC_OSX_FUSET)" "1"
	/usr/local/bin/packagesbuild $(BASE_DIR)/Setup/MacOSX/veracrypt_fuse-t.pkgproj
else
	/usr/local/bin/packagesbuild $(BASE_DIR)/Setup/MacOSX/veracrypt.pkgproj
endif
ifneq ("$(LOCAL_DEVELOPMENT_BUILD)","true")
	productsign --sign "Developer ID Installer: IDRIX (Z933746L2S)" --timestamp "$(BASE_DIR)/Setup/MacOSX/VeraCrypt $(TC_VERSION).pkg" $(BASE_DIR)/Setup/MacOSX/VeraCrypt_$(TC_VERSION).pkg
else
	# copy the unsigned package to the expected location
	cp "$(BASE_DIR)/Setup/MacOSX/VeraCrypt $(TC_VERSION).pkg" $(BASE_DIR)/Setup/MacOSX/VeraCrypt_$(TC_VERSION).pkg
endif
	rm -f $(APPNAME)_$(TC_VERSION).dmg
endif
	rm -f "$(BASE_DIR)/Setup/MacOSX/template.dmg"
	rm -fr "$(BASE_DIR)/Setup/MacOSX/VeraCrypt_dmg"
	mkdir -p "$(BASE_DIR)/Setup/MacOSX/VeraCrypt_dmg"
	bunzip2 -k -f "$(BASE_DIR)/Setup/MacOSX/template.dmg.bz2"
	hdiutil attach "$(BASE_DIR)/Setup/MacOSX/template.dmg" -noautoopen -quiet -mountpoint "$(BASE_DIR)/Setup/MacOSX/VeraCrypt_dmg"
	cp "$(BASE_DIR)/Setup/MacOSX/VeraCrypt_$(TC_VERSION).pkg" "$(BASE_DIR)/Setup/MacOSX/VeraCrypt_dmg/VeraCrypt_Installer.pkg"
	hdiutil detach "$(BASE_DIR)/Setup/MacOSX/VeraCrypt_dmg" -quiet -force
ifdef VC_LEGACY_BUILD
	hdiutil convert "$(BASE_DIR)/Setup/MacOSX/template.dmg" -quiet -format UDZO -imagekey zlib-level=9 -o $(APPNAME)_Legacy_$(TC_VERSION).dmg
else
	hdiutil convert "$(BASE_DIR)/Setup/MacOSX/template.dmg" -quiet -format UDZO -imagekey zlib-level=9 -o $(APPNAME)_$(TC_VERSION).dmg
endif
	rm -f "$(BASE_DIR)/Setup/MacOSX/template.dmg"
	rm -fr "$(BASE_DIR)/Setup/MacOSX/VeraCrypt_dmg"
endif



ifeq "$(PLATFORM)" "Linux"

# Packaging-tool feature probes. Empty result = host lacks the feature;
# the recipe falls back to the pre-PR (non-deterministic) form with a
# warning. $(strip) because $(shell) keeps trailing whitespace which
# would break the "= yes" equality test in the recipe.
#
# All probes act on a private $(mktemp) file and clean it up. touch
# probing /dev/null fails (EPERM) for unprivileged users and rewrites
# the device node as root. The tar option set requires GNU tar >= 1.28,
# so the probe exercises it exactly rather than matching "GNU tar".
# MAKESELF_TAR_EXTRA needs Makeself >= 2.3.1 (cited in the review).
TOUCH_REPRODUCIBLE      := $(strip $(shell t=$$(mktemp 2>/dev/null) && touch --no-dereference --date=@0 "$$t" >/dev/null 2>&1 && echo yes; rm -f "$$t"))
TAR_DETERMINISTIC       := $(strip $(shell t=$$(mktemp 2>/dev/null) && tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --mode='go-w,a+rX' --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime -cf "$$t" --files-from /dev/null >/dev/null 2>&1 && echo yes; rm -f "$$t"))
GZIP_NO_TIMESTAMP       := $(strip $(shell printf x | gzip -n -c >/dev/null 2>&1 && echo yes))
MAKESELF_PACKAGING_DATE := $(strip $(shell makeself --help 2>&1 | grep -q -- '--packaging-date' && echo yes))
MAKESELF_TAR_EXTRA      := $(strip $(shell makeself --help 2>&1 | grep -q -- '--tar-extra' && echo yes))
PYTHON_REPRO_FINALIZE   := $(strip $(shell for p in python3 python python2; do command -v $$p >/dev/null 2>&1 || continue; $$p -c 'import sys; v=sys.version_info; sys.exit(not (v[0] > 2 or (v[0] == 2 and v[1] >= 6)))' >/dev/null 2>&1 && command -v $$p && break; done))

INSTALL_UNINSTALLER ?= 1
INSTALL_LICENSE ?= 1
INSTALL_LICENSE_DIR ?= share/doc/$(APPNAME)
INSTALL_DOCS ?= 1
INSTALL_LANGUAGES ?= 1
INSTALL_MOUNT_HELPER ?= 1
INSTALL_MOUNT_HELPER_DIR ?= sbin
INSTALL_DESKTOP ?= 1
INSTALL_MIME ?= 1
INSTALL_ICONS ?= 1
INSTALL_APPIMAGE_FILES ?= 1
# Keep the former FUSE2-specific override working for existing packaging scripts.
ifeq "$(origin APPIMAGE_BUNDLE_FUSE)" "undefined"
ifeq "$(origin APPIMAGE_BUNDLE_FUSE2)" "undefined"
APPIMAGE_BUNDLE_FUSE := 1
else
APPIMAGE_BUNDLE_FUSE := $(APPIMAGE_BUNDLE_FUSE2)
endif
endif

# These override values are appended below usr and used in shell recipes.
# Keep command-line/environment overrides literal and path-like.
INSTALL_PATH_FORBIDDEN_HASH := \#
INSTALL_PATH_FORBIDDEN_CHARS := ' " ` $$ ( ) [ ] { } ; & | < > * ? ! ~ = : , @ % ^ \ $(INSTALL_PATH_FORBIDDEN_HASH)

define check_install_path
ifneq ($$(filter command line environment override,$$(origin $(1))),)
ifneq ($$(findstring $$$$,$$(value $(1))),)
$$(error $(1) must not contain make or shell variable expansions)
endif
endif
ifneq ($$(words $$($(1))),1)
$$(error $(1) must be a single relative path below usr without whitespace)
endif
ifneq ($$(filter /% ../% %/.. ..,$$($(1)))$$(findstring /../,$$($(1))),)
$$(error $(1) must be a relative path below usr without '..' components)
endif
ifneq ($$(strip $$(foreach c,$$(INSTALL_PATH_FORBIDDEN_CHARS),$$(findstring $$(c),$$($(1))))),)
$$(error $(1) contains unsupported characters; use only letters, digits, '/', '.', '_', '-' and '+')
endif
ifneq ($$(shell LC_ALL=C; case '$$($(1))' in (*[!A-Za-z0-9._+/-]*) printf invalid;; esac),)
$$(error $(1) contains unsupported characters; use only letters, digits, '/', '.', '_', '-' and '+')
endif
endef

$(eval $(call check_install_path,INSTALL_LICENSE_DIR))
$(eval $(call check_install_path,INSTALL_MOUNT_HELPER_DIR))

ifndef TC_NO_GUI
# The AppDir copy is only complete when its desktop integration payload is
# staged into usr first. Native packages can disable both sides together.
ifneq "$(INSTALL_APPIMAGE_FILES)" "0"
ifeq "$(INSTALL_DESKTOP)" "0"
$(error INSTALL_APPIMAGE_FILES requires INSTALL_DESKTOP=1; set INSTALL_APPIMAGE_FILES=0 when omitting desktop files)
endif
ifeq "$(INSTALL_MIME)" "0"
$(error INSTALL_APPIMAGE_FILES requires INSTALL_MIME=1; set INSTALL_APPIMAGE_FILES=0 when omitting MIME files)
endif
ifeq "$(INSTALL_ICONS)" "0"
$(error INSTALL_APPIMAGE_FILES requires INSTALL_ICONS=1; set INSTALL_APPIMAGE_FILES=0 when omitting icons)
endif
endif
endif

prepare: $(APPNAME)
	rm -fr $(BASE_DIR)/Setup/Linux/usr
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/bin
	cp $(BASE_DIR)/Main/$(APPNAME) $(BASE_DIR)/Setup/Linux/usr/bin/$(APPNAME)
ifneq "$(INSTALL_UNINSTALLER)" "0"
	cp $(BASE_DIR)/Setup/Linux/$(APPNAME)-uninstall.sh $(BASE_DIR)/Setup/Linux/usr/bin/$(APPNAME)-uninstall.sh
	chmod +x $(BASE_DIR)/Setup/Linux/usr/bin/$(APPNAME)-uninstall.sh
endif
ifneq "$(INSTALL_LICENSE)" "0"
	mkdir -p "$(BASE_DIR)/Setup/Linux/usr/$(INSTALL_LICENSE_DIR)"
	cp "$(BASE_DIR)/License.txt" "$(BASE_DIR)/Setup/Linux/usr/$(INSTALL_LICENSE_DIR)/License.txt"
endif
ifneq "$(INSTALL_DOCS)" "0"
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/doc/$(APPNAME)/HTML
	cp -R $(BASE_DIR)/../doc/html/* "$(BASE_DIR)/Setup/Linux/usr/share/doc/$(APPNAME)/HTML"
endif
ifneq "$(INSTALL_LANGUAGES)" "0"
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/veracrypt/languages
	cp -r $(BASE_DIR)/../Translations/* $(BASE_DIR)/Setup/Linux/usr/share/veracrypt/languages/
endif

ifneq "$(INSTALL_MOUNT_HELPER)" "0"
	mkdir -p "$(BASE_DIR)/Setup/Linux/usr/$(INSTALL_MOUNT_HELPER_DIR)"
	cp "$(BASE_DIR)/Setup/Linux/mount.$(APPNAME)" "$(BASE_DIR)/Setup/Linux/usr/$(INSTALL_MOUNT_HELPER_DIR)/mount.$(APPNAME)"
	chmod +x "$(BASE_DIR)/Setup/Linux/usr/$(INSTALL_MOUNT_HELPER_DIR)/mount.$(APPNAME)"
endif
ifndef TC_NO_GUI
ifneq "$(INSTALL_DESKTOP)" "0"
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/applications
	cp $(BASE_DIR)/Setup/Linux/$(APPNAME).desktop $(BASE_DIR)/Setup/Linux/usr/share/applications/$(APPNAME).desktop
endif
ifneq "$(INSTALL_MIME)" "0"
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/mime/packages
	cp $(BASE_DIR)/Setup/Linux/$(APPNAME).xml $(BASE_DIR)/Setup/Linux/usr/share/mime/packages/$(APPNAME).xml
endif

ifneq "$(INSTALL_ICONS)" "0"
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/pixmaps
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/icons/hicolor/scalable/apps
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/icons/hicolor/symbolic/apps
	cp $(BASE_DIR)/Resources/Icons/VeraCrypt-256x256.xpm $(BASE_DIR)/Setup/Linux/usr/share/pixmaps/$(APPNAME).xpm
	cp $(BASE_DIR)/Resources/Icons/VeraCrypt.svg $(BASE_DIR)/Setup/Linux/usr/share/icons/hicolor/scalable/apps/$(APPNAME).svg
	cp $(BASE_DIR)/Resources/Icons/VeraCrypt-symbolic.svg $(BASE_DIR)/Setup/Linux/usr/share/icons/hicolor/symbolic/apps/$(APPNAME)-symbolic.svg

	for res in 16 22 24 32 48 64 256 512 1024; do \
		mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/icons/hicolor/$${res}x$${res}/apps ;\
		cp $(BASE_DIR)/Resources/Icons/VeraCrypt-$${res}x$${res}.png $(BASE_DIR)/Setup/Linux/usr/share/icons/hicolor/$${res}x$${res}/apps/$(APPNAME).png ;\
	done
endif

ifneq "$(INSTALL_APPIMAGE_FILES)" "0"
	rm -fr $(BASE_DIR)/Setup/Linux/veracrypt.AppDir/usr
	cp -r $(BASE_DIR)/Setup/Linux/usr $(BASE_DIR)/Setup/Linux/veracrypt.AppDir/.
ifneq "$(APPIMAGE_BUNDLE_FUSE)" "0"
	@set -e; \
	_appdir="$(BASE_DIR)/Setup/Linux/veracrypt.AppDir"; \
	_fuse_soname=""; \
	_fuse_lib=""; \
	_fuse_link_name=""; \
	_fuse_lib_prefix=""; \
	case "$(VC_FUSE_PACKAGE)" in \
		fuse3) _fuse_link_name="libfuse3.so"; _fuse_lib_prefix="libfuse3.so." ;; \
		fuse) _fuse_link_name="libfuse.so"; _fuse_lib_prefix="libfuse.so." ;; \
	esac; \
	_fuse_soname_from_name() { \
		printf '%s\n' "$$1" | awk '{ if (match($$0, /^libfuse(3)?\.so\.[0-9]+/)) { print substr($$0, RSTART, RLENGTH); exit } }'; \
	}; \
	_fuse_search_dirs() { \
		$(PKG_CONFIG) --variable=libdir "$(VC_FUSE_PACKAGE)" 2>/dev/null || true; \
		$(PKG_CONFIG) --libs-only-L "$(VC_FUSE_PACKAGE)" 2>/dev/null | tr ' ' '\n' | sed 's/^-L//' || true; \
		printf '%s\n' /lib64 /usr/lib64 /lib /usr/lib /lib/* /usr/lib/*; \
	}; \
	if command -v readelf >/dev/null 2>&1; then \
		_fuse_soname="$$(readelf -d "$$_appdir/usr/bin/$(APPNAME)" 2>/dev/null | awk -F'[][]' '/NEEDED/ && $$2 ~ /^libfuse(3)?\.so\./ { print $$2; exit }')"; \
	fi; \
	if [ -z "$$_fuse_soname" ] && [ -n "$$_fuse_link_name" ]; then \
		for _candidate_dir in $$( _fuse_search_dirs ); do \
			[ -n "$$_candidate_dir" ] || continue; \
			_candidate="$$_candidate_dir/$$_fuse_link_name"; \
			if [ -e "$$_candidate" ]; then \
				_fuse_target="$$(readlink "$$_candidate" 2>/dev/null || true)"; \
				_fuse_real="$$(readlink -f "$$_candidate" 2>/dev/null || true)"; \
				if [ -n "$$_fuse_target" ]; then \
					_fuse_soname="$$( _fuse_soname_from_name "$$(basename "$$_fuse_target")" )"; \
				fi; \
				if [ -z "$$_fuse_soname" ]; then \
					if [ -n "$$_fuse_real" ]; then \
						_fuse_soname="$$( _fuse_soname_from_name "$$(basename "$$_fuse_real")" )"; \
					fi; \
				fi; \
				if [ -n "$$_fuse_soname" ]; then \
					if [ -e "$$_candidate_dir/$$_fuse_soname" ]; then \
						_fuse_lib="$$_candidate_dir/$$_fuse_soname"; \
					elif [ -n "$$_fuse_real" ]; then \
						_fuse_lib="$$_fuse_real"; \
					fi; \
					break; \
				fi; \
			fi; \
		done; \
	fi; \
	if [ -z "$$_fuse_lib" ] && [ -z "$$_fuse_soname" ] && [ -n "$$_fuse_lib_prefix" ]; then \
		_fuse_soname="$$( (ldconfig -p 2>/dev/null || /sbin/ldconfig -p 2>/dev/null || true) | awk -v prefix="$$_fuse_lib_prefix" 'index($$1, prefix) == 1 { print $$1; exit }')"; \
	fi; \
	if [ -z "$$_fuse_lib" ] && [ -z "$$_fuse_soname" ] && [ -n "$$_fuse_lib_prefix" ]; then \
		for _candidate_dir in $$( _fuse_search_dirs ); do \
			[ -n "$$_candidate_dir" ] || continue; \
			for _candidate in "$$_candidate_dir"/"$$_fuse_lib_prefix"*; do \
				if [ -e "$$_candidate" ]; then \
					_fuse_soname="$$( _fuse_soname_from_name "$$(basename "$$_candidate")" )"; \
					if [ -n "$$_fuse_soname" ]; then \
						_fuse_lib="$$_candidate"; \
						break; \
					fi; \
				fi; \
			done; \
			[ -n "$$_fuse_soname" ] && break; \
		done; \
	fi; \
	if [ -z "$$_fuse_soname" ]; then \
		case "$(VC_FUSE_PACKAGE)" in \
			fuse) _fuse_soname="libfuse.so.2" ;; \
		esac; \
	fi; \
	if [ -z "$$_fuse_lib" ] && [ -n "$$_fuse_soname" ]; then \
		for _candidate_dir in $$( _fuse_search_dirs ); do \
			[ -n "$$_candidate_dir" ] || continue; \
			_candidate="$$_candidate_dir/$$_fuse_soname"; \
			if [ -e "$$_candidate" ]; then _fuse_lib="$$_candidate"; break; fi; \
		done; \
	fi; \
	if [ -z "$$_fuse_lib" ] && [ -n "$$_fuse_soname" ]; then \
		_fuse_lib="$$( (ldconfig -p 2>/dev/null || /sbin/ldconfig -p 2>/dev/null || true) | awk -v soname="$$_fuse_soname" '$$1 == soname { print $$NF; exit }')"; \
	fi; \
	if [ -z "$$_fuse_lib" ] && [ -n "$$_fuse_soname" ]; then \
		for _candidate in /lib64/"$$_fuse_soname" /usr/lib64/"$$_fuse_soname" /lib/"$$_fuse_soname" /usr/lib/"$$_fuse_soname" /lib/*/"$$_fuse_soname" /usr/lib/*/"$$_fuse_soname"; do \
			if [ -e "$$_candidate" ]; then _fuse_lib="$$_candidate"; break; fi; \
		done; \
	fi; \
	if [ -n "$$_fuse_lib" ]; then \
		mkdir -p "$$_appdir/usr/lib"; \
		rm -f "$$_appdir/usr/lib"/libfuse.so "$$_appdir/usr/lib"/libfuse.so.* "$$_appdir/usr/lib"/libfuse3.so "$$_appdir/usr/lib"/libfuse3.so.*; \
		echo "Bundling AppImage FUSE userspace library ($$_fuse_soname): $$_fuse_lib"; \
		cp -P "$$_fuse_lib" "$$_appdir/usr/lib/"; \
		_fuse_real="$$(readlink -f "$$_fuse_lib" 2>/dev/null || true)"; \
		if [ -n "$$_fuse_real" ] && [ "$$_fuse_real" != "$$_fuse_lib" ]; then \
			cp "$$_fuse_real" "$$_appdir/usr/lib/"; \
		fi; \
		if [ -n "$$_fuse_real" ] && [ -n "$$_fuse_soname" ] && [ ! -e "$$_appdir/usr/lib/$$_fuse_soname" ]; then \
			ln -s "$$(basename "$$_fuse_real")" "$$_appdir/usr/lib/$$_fuse_soname"; \
		fi; \
	else \
		if [ -n "$$_fuse_soname" ]; then \
			echo "Warning: $$_fuse_soname not found; AppImage will rely on a host FUSE userspace library"; \
		else \
			echo "Warning: FUSE userspace library not found; AppImage will rely on a host FUSE userspace library"; \
		fi; \
	fi
endif
ifneq "$(INSTALL_ICONS)" "0"
	ln -sf usr/share/icons/hicolor/1024x1024/apps/$(APPNAME).png $(BASE_DIR)/Setup/Linux/veracrypt.AppDir/$(APPNAME).png
endif
endif
endif
	# Normalise modification times of every staged file. cp preserves the
	# checkout-time mtimes of the source tree, which would otherwise leak
	# into the tar/makeself archives and break reproducibility.
	# Only run when GNU touch supports the option set. AppImage staging is
	# clamped too; appimagetool honours SOURCE_DATE_EPOCH for its SquashFS
	# metadata, and the AppDir input should not leak checkout/build mtimes.
ifeq "$(TOUCH_REPRODUCIBLE)" "yes"
	_appdir="$(BASE_DIR)/Setup/Linux/veracrypt.AppDir"; \
	if [ ! -d "$$_appdir" ]; then \
		_appdir=""; \
	fi; \
	find $(BASE_DIR)/Setup/Linux/usr $$_appdir \
		-exec touch --no-dereference --date=@$(SOURCE_DATE_EPOCH) {} +
else
	@echo "Reproducible build: GNU touch unavailable, skipping mtime normalisation"
endif


install: prepare
ifneq "$(DESTDIR)" ""
	mkdir -p $(DESTDIR)
endif
	cp -R $(BASE_DIR)/Setup/Linux/usr $(DESTDIR)/

ifeq "$(TC_BUILD_CONFIG)" "Release"
package: prepare
	# Deterministic tarball: sort members, pin mtime to SOURCE_DATE_EPOCH,
	# drop owner/group identity, and use gzip -n so no timestamp/name is
	# stored in the gzip header.
	# --mode= normalises permission bits so the host umask cannot leak
	# into them. Falls back to plain tar cfz when probes fail.
ifeq "$(TAR_DETERMINISTIC)$(GZIP_NO_TIMESTAMP)" "yesyes"
	tar --sort=name --mtime=@$(SOURCE_DATE_EPOCH) \
		--owner=0 --group=0 --numeric-owner \
		--mode='go-w,a+rX' \
		--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
		-cf $(BASE_DIR)/Setup/Linux/$(APPNAME)_$(TC_VERSION).tar \
		--directory $(BASE_DIR)/Setup/Linux usr
	gzip -9 -n -c $(BASE_DIR)/Setup/Linux/$(APPNAME)_$(TC_VERSION).tar \
		> $(BASE_DIR)/Setup/Linux/$(PACKAGE_NAME)
	rm -f $(BASE_DIR)/Setup/Linux/$(APPNAME)_$(TC_VERSION).tar
else
	@echo "Reproducible build: non-deterministic tar.gz fallback (GNU tar=$(if $(TAR_DETERMINISTIC),yes,no), gzip -n=$(if $(GZIP_NO_TIMESTAMP),yes,no))"
	tar cfz $(BASE_DIR)/Setup/Linux/$(PACKAGE_NAME) --directory $(BASE_DIR)/Setup/Linux usr
endif

	@rm -fr $(INTERNAL_INSTALLER_NAME)
	@echo "#!/bin/sh" > $(INTERNAL_INSTALLER_NAME)
	@echo "VERSION=$(TC_VERSION)" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_TYPE=tar" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_NAME=$(PACKAGE_NAME)" >> $(INTERNAL_INSTALLER_NAME)
	@template_lines=$$(wc -l < $(BASE_DIR)/Setup/Linux/veracrypt_install_template.sh); \
	echo "PACKAGE_START=$$(($$template_lines + 7))" >> $(INTERNAL_INSTALLER_NAME)
	@echo "INSTALLER_TYPE=$(INSTALLER_TYPE)" >> $(INTERNAL_INSTALLER_NAME)

	@cat $(BASE_DIR)/Setup/Linux/veracrypt_install_template.sh >> $(INTERNAL_INSTALLER_NAME)
	@cat $(BASE_DIR)/Setup/Linux/$(PACKAGE_NAME) >> $(INTERNAL_INSTALLER_NAME)
	chmod +x $(INTERNAL_INSTALLER_NAME)

	rm -fr $(BASE_DIR)/Setup/Linux/packaging
	mkdir -p $(BASE_DIR)/Setup/Linux/packaging
	cp $(INTERNAL_INSTALLER_NAME) $(BASE_DIR)/Setup/Linux/packaging/.
	# makeself: --packaging-date pins the banner date, SOURCE_DATE_EPOCH is
	# honoured by the embedded tar/gzip, and the archive is sorted so the
	# self-extracting installer is byte-identical across builds.
	# Flags gated per probe; invoked from Setup/Linux with relative paths
	# so the build path does not end up in makeself's echoed argv.
	@cd $(BASE_DIR)/Setup/Linux && set --; \
	if [ "$(MAKESELF_PACKAGING_DATE)" = yes ]; then \
		set -- "$$@" --packaging-date "@$(SOURCE_DATE_EPOCH)"; \
	fi; \
	if [ "$(MAKESELF_TAR_EXTRA)" = yes ] && [ "$(TAR_DETERMINISTIC)" = yes ]; then \
		set -- "$$@" --tar-extra "--sort=name --mtime=@$(SOURCE_DATE_EPOCH) --owner=0 --group=0 --numeric-owner --mode=go-w,a+rX"; \
	fi; \
	if [ "$$#" -eq 0 ]; then \
		echo "Reproducible build: makeself flags unavailable, installer will not be byte-identical"; \
	fi; \
	makeself "$$@" \
		packaging "$(INSTALLER_NAME)" \
		"VeraCrypt $(TC_VERSION) Installer" "./$(INTERNAL_INSTALLER_NAME)"
	# makeself runs 'gzip -c9 < tmpfile' which writes tmpfile's mtime into
	# the gzip header (SOURCE_DATE_EPOCH is ignored for redirected stdin).
	# Zero the mtime and refresh CRCsum/MD5; installer --check still passes.
	@if [ -n "$(PYTHON_REPRO_FINALIZE)" ]; then \
		"$(PYTHON_REPRO_FINALIZE)" "$(BASE_DIR)/Build/Tools/makeself_repro_finalize.py" \
			"$(BASE_DIR)/Setup/Linux/$(INSTALLER_NAME)"; \
	else \
		echo "Reproducible build: Python 2.6+ unavailable, skipping makeself finalize"; \
	fi

appimage: prepare
	@set -e; \
	_appimagetool_arch_suffix=""; \
	_final_appimage_arch_suffix=""; \
	case "$(CPU_ARCH)" in \
		x86) \
			_appimagetool_arch_suffix="i686"; \
			_final_appimage_arch_suffix="i686"; \
			;; \
		x64) \
			_appimagetool_arch_suffix="x86_64"; \
			_final_appimage_arch_suffix="x86_64"; \
			;; \
		arm64) \
			_appimagetool_arch_suffix="aarch64"; \
			_final_appimage_arch_suffix="aarch64"; \
			;; \
		arm7) \
			_appimagetool_arch_suffix="armhf"; \
			_final_appimage_arch_suffix="armhf"; \
			;; \
		*) \
			echo "Error: Unsupported CPU_ARCH for AppImage: $(CPU_ARCH). Supported: x86, x64, arm64, arm7" >&2; \
			exit 1; \
			;; \
	esac; \
	_appimagetool_executable_name="appimagetool-$${_appimagetool_arch_suffix}.AppImage"; \
	_appimagetool_executable_path="$(BASE_DIR)/Setup/Linux/$${_appimagetool_executable_name}"; \
	_appimagetool_url="https://github.com/AppImage/appimagetool/releases/download/continuous/$${_appimagetool_executable_name}"; \
	_final_appimage_gtk_suffix=""; \
	if [ "$(GTK_VERSION)" = "2" ]; then \
		_final_appimage_gtk_suffix="-gtk2-legacy"; \
	fi; \
	_final_appimage_filename="VeraCrypt-$(TC_VERSION)$${_final_appimage_gtk_suffix}-$${_final_appimage_arch_suffix}.AppImage"; \
	_final_appimage_path="$(BASE_DIR)/Setup/Linux/$${_final_appimage_filename}"; \
	\
	echo "Preparing AppImage for $(CPU_ARCH) (using $${_appimagetool_arch_suffix})..."; \
	echo "Downloading appimagetool from $${_appimagetool_url}..."; \
	wget --quiet -O "$${_appimagetool_executable_path}" "$${_appimagetool_url}"; \
	chmod +x "$${_appimagetool_executable_path}"; \
	echo "Creating AppImage $${_final_appimage_path}..."; \
	ARCH="$${_final_appimage_arch_suffix}" "$${_appimagetool_executable_path}" "$(BASE_DIR)/Setup/Linux/veracrypt.AppDir" "$${_final_appimage_path}"; \
	echo "AppImage created: $${_final_appimage_path}"; \
	echo "Cleaning up appimagetool..."; \
	rm -f "$${_appimagetool_executable_path}";

endif

endif

ifeq "$(PLATFORM)" "FreeBSD"
prepare: $(APPNAME)
	rm -fr $(BASE_DIR)/Setup/FreeBSD/usr
	mkdir -p $(BASE_DIR)/Setup/FreeBSD/usr/bin
	mkdir -p $(BASE_DIR)/Setup/FreeBSD/usr/share/doc/$(APPNAME)/HTML
	cp $(BASE_DIR)/Main/$(APPNAME) $(BASE_DIR)/Setup/FreeBSD/usr/bin/$(APPNAME)
	cp $(BASE_DIR)/Setup/FreeBSD/$(APPNAME)-uninstall.sh $(BASE_DIR)/Setup/FreeBSD/usr/bin/$(APPNAME)-uninstall.sh
	chmod +x $(BASE_DIR)/Setup/FreeBSD/usr/bin/$(APPNAME)-uninstall.sh
	cp $(BASE_DIR)/License.txt $(BASE_DIR)/Setup/FreeBSD/usr/share/doc/$(APPNAME)/License.txt
	cp -R $(BASE_DIR)/../doc/html/* "$(BASE_DIR)/Setup/FreeBSD/usr/share/doc/$(APPNAME)/HTML"
	mkdir -p $(BASE_DIR)/Setup/FreeBSD/usr/share/veracrypt/languages
	cp -r $(BASE_DIR)/../Translations/* $(BASE_DIR)/Setup/FreeBSD/usr/share/veracrypt/languages/

ifndef TC_NO_GUI
	mkdir -p $(BASE_DIR)/Setup/FreeBSD/usr/local/share/applications
	mkdir -p $(BASE_DIR)/Setup/FreeBSD/usr/local/share/mime/packages
	cp $(BASE_DIR)/Setup/FreeBSD/$(APPNAME).desktop $(BASE_DIR)/Setup/FreeBSD/usr/local/share/applications/$(APPNAME).desktop
	cp $(BASE_DIR)/Setup/FreeBSD/$(APPNAME).xml $(BASE_DIR)/Setup/FreeBSD/usr/local/share/mime/packages/$(APPNAME).xml

	mkdir -p $(BASE_DIR)/Setup/FreeBSD/usr/local/share/pixmaps
	mkdir -p $(BASE_DIR)/Setup/FreeBSD/usr/local/share/icons/hicolor/scalable/apps
	mkdir -p $(BASE_DIR)/Setup/FreeBSD/usr/local/share/icons/hicolor/symbolic/apps
	cp $(BASE_DIR)/Resources/Icons/VeraCrypt-256x256.xpm $(BASE_DIR)/Setup/FreeBSD/usr/local/share/pixmaps/$(APPNAME).xpm
	cp $(BASE_DIR)/Resources/Icons/VeraCrypt.svg $(BASE_DIR)/Setup/FreeBSD/usr/local/share/icons/hicolor/scalable/apps/$(APPNAME).svg
	cp $(BASE_DIR)/Resources/Icons/VeraCrypt-symbolic.svg $(BASE_DIR)/Setup/FreeBSD/usr/local/share/icons/hicolor/symbolic/apps/$(APPNAME)-symbolic.svg

	for res in 16 22 24 32 48 64 256 512 1024; do \
		mkdir -p $(BASE_DIR)/Setup/FreeBSD/usr/local/share/icons/hicolor/$${res}x$${res}/apps ;\
		cp $(BASE_DIR)/Resources/Icons/VeraCrypt-$${res}x$${res}.png $(BASE_DIR)/Setup/FreeBSD/usr/local/share/icons/hicolor/$${res}x$${res}/apps/$(APPNAME).png ;\
	done
endif
	chown -R root:wheel $(BASE_DIR)/Setup/FreeBSD/usr
	chmod -R go-w $(BASE_DIR)/Setup/FreeBSD/usr


install: prepare
ifneq "$(DESTDIR)" ""
	mkdir -p $(DESTDIR)
endif
	cp -R $(BASE_DIR)/Setup/FreeBSD/usr $(DESTDIR)/.

ifeq "$(TC_BUILD_CONFIG)" "Release"
package: prepare
	tar cfz $(BASE_DIR)/Setup/FreeBSD/$(PACKAGE_NAME) --directory $(BASE_DIR)/Setup/FreeBSD usr

	@rm -fr $(INTERNAL_INSTALLER_NAME)
	@echo "#!/bin/sh" > $(INTERNAL_INSTALLER_NAME)
	@echo "VERSION=$(TC_VERSION)" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_TYPE=tar" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_NAME=$(PACKAGE_NAME)" >> $(INTERNAL_INSTALLER_NAME)
	@template_lines=$$(wc -l < $(BASE_DIR)/Setup/FreeBSD/veracrypt_install_template.sh); \
	echo "PACKAGE_START=$$(($$template_lines + 7))" >> $(INTERNAL_INSTALLER_NAME)
	@echo "INSTALLER_TYPE=$(INSTALLER_TYPE)" >> $(INTERNAL_INSTALLER_NAME)

	@cat $(BASE_DIR)/Setup/FreeBSD/veracrypt_install_template.sh >> $(INTERNAL_INSTALLER_NAME)
	@cat $(BASE_DIR)/Setup/FreeBSD/$(PACKAGE_NAME) >> $(INTERNAL_INSTALLER_NAME)
	chmod +x $(INTERNAL_INSTALLER_NAME)

	rm -fr $(BASE_DIR)/Setup/FreeBSD/packaging
	mkdir -p $(BASE_DIR)/Setup/FreeBSD/packaging
	cp $(INTERNAL_INSTALLER_NAME) $(BASE_DIR)/Setup/FreeBSD/packaging/.
	makeself $(BASE_DIR)/Setup/FreeBSD/packaging $(BASE_DIR)/Setup/FreeBSD/$(INSTALLER_NAME) "VeraCrypt $(TC_VERSION) $(SYSTEMNAME) Installer" ./$(INTERNAL_INSTALLER_NAME)

endif

endif

$(OBJS): $(PCH)

Resources.o: $(RESOURCES)

LanguageStrings.o: $(RESOURCES)

include $(BUILD_INC)/Makefile.inc
