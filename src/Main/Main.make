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

export TC_VERSION := $(shell grep VERSION_STRING ../Common/Tcdefs.h | head -n 1 | cut -d'"' -f 2)

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

$(APPNAME): $(LIBS) $(OBJS)
	@echo Linking $@
	$(CXX) -o $(APPNAME) $(OBJS) -Wl,--whole-archive $(OPENADP_LIBS) -Wl,--no-whole-archive $(LIBS) $(AYATANA_LIBS) $(FUSE_LIBS) $(WX_LIBS) $(LFLAGS)

ifeq "$(TC_BUILD_CONFIG)" "Release"
ifndef NOSTRIP
	strip $(APPNAME)
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
	mkdir -p $(APPNAME).app/Contents/MacOS $(APPNAME).app/Contents/Resources/doc/HTML
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
prepare: $(APPNAME)
	rm -fr $(BASE_DIR)/Setup/Linux/usr
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/bin
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/doc/$(APPNAME)/HTML
	cp $(BASE_DIR)/Main/$(APPNAME) $(BASE_DIR)/Setup/Linux/usr/bin/$(APPNAME)
	cp $(BASE_DIR)/Setup/Linux/$(APPNAME)-uninstall.sh $(BASE_DIR)/Setup/Linux/usr/bin/$(APPNAME)-uninstall.sh
	chmod +x $(BASE_DIR)/Setup/Linux/usr/bin/$(APPNAME)-uninstall.sh
	cp $(BASE_DIR)/License.txt $(BASE_DIR)/Setup/Linux/usr/share/doc/$(APPNAME)/License.txt
	cp -R $(BASE_DIR)/../doc/html/* "$(BASE_DIR)/Setup/Linux/usr/share/doc/$(APPNAME)/HTML"
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/veracrypt/languages
	cp -r $(BASE_DIR)/../Translations/* $(BASE_DIR)/Setup/Linux/usr/share/veracrypt/languages/

	mkdir -p $(BASE_DIR)/Setup/Linux/usr/sbin
	cp $(BASE_DIR)/Setup/Linux/mount.$(APPNAME) $(BASE_DIR)/Setup/Linux/usr/sbin/mount.$(APPNAME)
	chmod +x $(BASE_DIR)/Setup/Linux/usr/sbin/mount.$(APPNAME)
ifndef TC_NO_GUI
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/applications
	mkdir -p $(BASE_DIR)/Setup/Linux/usr/share/mime/packages
	cp $(BASE_DIR)/Setup/Linux/$(APPNAME).desktop $(BASE_DIR)/Setup/Linux/usr/share/applications/$(APPNAME).desktop
	cp $(BASE_DIR)/Setup/Linux/$(APPNAME).xml $(BASE_DIR)/Setup/Linux/usr/share/mime/packages/$(APPNAME).xml

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

	rm -fr $(BASE_DIR)/Setup/Linux/veracrypt.AppDir/usr
	cp -r $(BASE_DIR)/Setup/Linux/usr $(BASE_DIR)/Setup/Linux/veracrypt.AppDir/.
	ln -sf usr/share/icons/hicolor/1024x1024/apps/$(APPNAME).png $(BASE_DIR)/Setup/Linux/veracrypt.AppDir/$(APPNAME).png
endif


install: prepare
ifneq "$(DESTDIR)" ""
	mkdir -p $(DESTDIR)
endif
	cp -R $(BASE_DIR)/Setup/Linux/usr $(DESTDIR)/

ifeq "$(TC_BUILD_CONFIG)" "Release"
package: prepare
	tar cfz $(BASE_DIR)/Setup/Linux/$(PACKAGE_NAME) --directory $(BASE_DIR)/Setup/Linux usr

	@rm -fr $(INTERNAL_INSTALLER_NAME)
	@echo "#!/bin/sh" > $(INTERNAL_INSTALLER_NAME)
	@echo "VERSION=$(TC_VERSION)" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_TYPE=tar" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_NAME=$(PACKAGE_NAME)" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_START=1112" >> $(INTERNAL_INSTALLER_NAME)
	@echo "INSTALLER_TYPE=$(INSTALLER_TYPE)" >> $(INTERNAL_INSTALLER_NAME)

	@cat $(BASE_DIR)/Setup/Linux/veracrypt_install_template.sh >> $(INTERNAL_INSTALLER_NAME)
	@cat $(BASE_DIR)/Setup/Linux/$(PACKAGE_NAME) >> $(INTERNAL_INSTALLER_NAME)
	chmod +x $(INTERNAL_INSTALLER_NAME)

	rm -fr $(BASE_DIR)/Setup/Linux/packaging
	mkdir -p $(BASE_DIR)/Setup/Linux/packaging
	cp $(INTERNAL_INSTALLER_NAME) $(BASE_DIR)/Setup/Linux/packaging/.
	makeself $(BASE_DIR)/Setup/Linux/packaging $(BASE_DIR)/Setup/Linux/$(INSTALLER_NAME) "VeraCrypt $(TC_VERSION) Installer" ./$(INTERNAL_INSTALLER_NAME)

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
	_final_appimage_filename="VeraCrypt-$(TC_VERSION)-$${_final_appimage_arch_suffix}.AppImage"; \
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
	@echo "PACKAGE_START=1108" >> $(INTERNAL_INSTALLER_NAME)
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
