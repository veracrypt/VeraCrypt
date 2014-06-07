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

TC_VERSION = $(shell grep VERSION_STRING ../Common/Tcdefs.h | head -n 1 | cut -d'"' -f 2)

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
	
ifeq "$(TC_BUILD_CONFIG)" "Release"
	cp $(PWD)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)
else
	-ln -sf $(PWD)/Main/$(APPNAME) $(APPNAME).app/Contents/MacOS/$(APPNAME)
endif

	cp $(PWD)/Resources/Icons/VeraCrypt.icns $(APPNAME).app/Contents/Resources
	
	echo -n APPLTRUE >$(APPNAME).app/Contents/PkgInfo
	sed -e 's/_VERSION_/$(patsubst %a,%.1,$(patsubst %b,%.2,$(TC_VERSION)))/' ../Build/Resources/MacOSX/Info.plist.xml >$(APPNAME).app/Contents/Info.plist
endif


$(OBJS): $(PCH)

Resources.o: $(RESOURCES)

include $(BUILD_INC)/Makefile.inc
