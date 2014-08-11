#
# Copyright (c) 2008-2009 TrueCrypt Developers Association. All rights reserved.
#
# Governed by the TrueCrypt License 3.0 the full text of which is contained in
# the file License.txt included in TrueCrypt binary and source code distribution
# packages.
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
OBJS += Forms/VolumeSizeWizardPage.o
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

FUSE_LIBS = $(shell pkg-config fuse --libs)


#------ Executable ------

export TC_VERSION := $(shell grep VERSION_STRING ../Common/Tcdefs.h | head -n 1 | cut -d'"' -f 2)

#------ Linux package naming ------
ifeq "$(PLATFORM)" "Linux"

ifdef TC_NO_GUI
INSTALLER_TYPE := console
PACKAGE_NAME := $(APPNAME)_$(TC_VERSION)_console_$(PLATFORM_ARCH).tar.gz
else
INSTALLER_TYPE := gui
PACKAGE_NAME := $(APPNAME)_$(TC_VERSION)_$(PLATFORM_ARCH).tar.gz
endif

INTERNAL_INSTALLER_NAME := veracrypt_install_$(INSTALLER_TYPE)_$(CPU_ARCH).sh
INSTALLER_NAME := veracrypt-$(TC_VERSION)-setup-$(INSTALLER_TYPE)-$(CPU_ARCH)

endif
#-----------------------------------

$(APPNAME): $(LIBS) $(OBJS)
	@echo Linking $@
	$(CXX) -o $(APPNAME) $(LFLAGS) $(OBJS) $(LIBS) $(FUSE_LIBS) $(WX_LIBS)

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
	mkdir -p $(APPNAME).app/Contents/MacOS $(APPNAME).app/Contents/Resources
	-rm -f $(APPNAME).app/Contents/MacOS/$(APPNAME)
	-rm -f $(APPNAME).app/Contents/MacOS/$(APPNAME)_console
	
ifeq "$(TC_BUILD_CONFIG)" "Release"
ifdef TC_NO_GUI
	cp $(PWD)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)_console
else
	cp $(PWD)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)
endif
else
ifdef TC_NO_GUI
	-rm -f $(PWD)/Main/$(APPNAME)_console
	cp $(PWD)/Main/$(APPNAME) $(PWD)/Main/$(APPNAME)_console
	-ln -sf $(PWD)/Main/$(APPNAME)_console $(APPNAME).app/Contents/MacOS/$(APPNAME)_console
else
	-ln -sf $(PWD)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)
endif
endif

	cp $(PWD)/Resources/Icons/VeraCrypt.icns $(APPNAME).app/Contents/Resources
	cp "$(PWD)/Release/Setup Files/VeraCrypt User Guide.pdf" $(APPNAME).app/Contents/Resources
	
	echo -n APPLTRUE >$(APPNAME).app/Contents/PkgInfo
	sed -e 's/_VERSION_/$(patsubst %a,%.1,$(patsubst %b,%.2,$(TC_VERSION)))/' ../Build/Resources/MacOSX/Info.plist.xml >$(APPNAME).app/Contents/Info.plist
	codesign -s "Developer ID Application: Mounir IDRASSI" $(APPNAME).app
	/usr/local/bin/packagesbuild $(PWD)/Setup/MacOSX/veracrypt.pkgproj
	productsign --sign "Developer ID Installer: Mounir IDRASSI" "$(PWD)/Setup/MacOSX/VeraCrypt $(TC_VERSION).pkg" $(PWD)/Setup/MacOSX/VeraCrypt_$(TC_VERSION).pkg
	rm -f $(APPNAME)_$(TC_VERSION).dmg
	hdiutil create -srcfolder $(PWD)/Setup/MacOSX/VeraCrypt_$(TC_VERSION).pkg -volname "VeraCrypt $(TC_VERSION) for Mac OS X $(VC_OSX_TARGET) and later" $(APPNAME)_$(TC_VERSION).dmg
endif

ifeq "$(PLATFORM)" "Linux"	
ifeq "$(TC_BUILD_CONFIG)" "Release"
	mkdir -p $(PWD)/Setup/Linux/usr/bin
	mkdir -p $(PWD)/Setup/Linux/usr/share/$(APPNAME)/doc
	cp $(PWD)/Main/$(APPNAME) $(PWD)/Setup/Linux/usr/bin/$(APPNAME)
	cp $(PWD)/Setup/Linux/$(APPNAME)-uninstall.sh $(PWD)/Setup/Linux/usr/bin/$(APPNAME)-uninstall.sh
	chmod +x $(PWD)/Setup/Linux/usr/bin/$(APPNAME)-uninstall.sh
	cp $(PWD)/License.txt $(PWD)/Setup/Linux/usr/share/$(APPNAME)/doc/License.txt
	cp "$(PWD)/Release/Setup Files/VeraCrypt User Guide.pdf" "$(PWD)/Setup/Linux/usr/share/$(APPNAME)/doc/VeraCrypt User Guide.pdf"

ifndef TC_NO_GUI
	mkdir -p $(PWD)/Setup/Linux/usr/share/applications
	mkdir -p $(PWD)/Setup/Linux/usr/share/pixmaps
	cp $(PWD)/Resources/Icons/VeraCrypt-48x48.xpm $(PWD)/Setup/Linux/usr/share/pixmaps/$(APPNAME).xpm
	cp $(PWD)/Setup/Linux/$(APPNAME).desktop $(PWD)/Setup/Linux/usr/share/applications/$(APPNAME).desktop
endif


	tar cfz $(PWD)/Setup/Linux/$(PACKAGE_NAME) --directory $(PWD)/Setup/Linux usr
	
	@rm -fr $(INTERNAL_INSTALLER_NAME)
	@echo "#!/bin/sh" > $(INTERNAL_INSTALLER_NAME)
	@echo "VERSION=$(TC_VERSION)" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_TYPE=tar" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_NAME=$(PACKAGE_NAME)" >> $(INTERNAL_INSTALLER_NAME)
	@echo "PACKAGE_START=841" >> $(INTERNAL_INSTALLER_NAME)
	@echo "INSTALLER_TYPE=$(INSTALLER_TYPE)" >> $(INTERNAL_INSTALLER_NAME)
	
	@cat $(PWD)/Setup/Linux/veracrypt_install_template.sh >> $(INTERNAL_INSTALLER_NAME)
	@cat $(PWD)/Setup/Linux/$(PACKAGE_NAME) >> $(INTERNAL_INSTALLER_NAME)
	chmod +x $(INTERNAL_INSTALLER_NAME)

	rm -fr $(PWD)/Setup/Linux/packaging
	mkdir -p $(PWD)/Setup/Linux/packaging
	cp $(INTERNAL_INSTALLER_NAME) $(PWD)/Setup/Linux/packaging/.
	makeself $(PWD)/Setup/Linux/packaging $(PWD)/Setup/Linux/$(INSTALLER_NAME) "VeraCrypt $(TC_VERSION) Installer" ./$(INTERNAL_INSTALLER_NAME)

endif

endif

$(OBJS): $(PCH)

Resources.o: $(RESOURCES)

include $(BUILD_INC)/Makefile.inc
