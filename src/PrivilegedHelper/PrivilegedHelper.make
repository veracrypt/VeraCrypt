#
# Copyright (c) 2026 AM Crypto and are governed by the Apache License 2.0
# the full text of which is contained in the file License.txt included in
# VeraCrypt binary and source code distribution packages.
#
# Builds the VeraCrypt privileged helper (macOS, SMJobBless). Produced as a
# self-contained Mach-O tool with its Info.plist and launchd plist embedded in
# dedicated __TEXT sections, as required by SMJobBless. Invoked from the macOS
# "prepare" target in Main/Main.make.
#
# Relies on CXXFLAGS / LFLAGS exported by the top-level Makefile (architecture,
# SDK, deployment target and -framework Security are already present there) and
# on TC_VERSION / VC_OSX_TEAM_ID.

HELPER_LABEL := org.idrix.VeraCrypt.helper

# Mirror the version normalisation used for the application Info.plist.
HELPER_VERSION := $(patsubst %a,%.1,$(patsubst %b,%.2,$(TC_VERSION)))

HELPER_INFO_PLIST    := Helper-Info.plist
HELPER_LAUNCHD_PLIST := Helper-Launchd.plist
HELPER_INFO_TEMPLATE    := $(BASE_DIR)/Build/Resources/MacOSX/Helper-Info.plist.xml
HELPER_LAUNCHD_TEMPLATE := $(BASE_DIR)/Build/Resources/MacOSX/Helper-Launchd.plist.xml

# The generated plists are .PHONY so they are regenerated on every build: their
# content depends on VC_OSX_TEAM_ID / TC_VERSION (not just the template), so a
# rebuild after changing the Team ID must re-embed the new code-signing
# requirement. Otherwise a stale Team ID in the helper's SMAuthorizedClients
# breaks the SMJobBless reciprocal-signature check.
.PHONY: helper clean $(HELPER_INFO_PLIST) $(HELPER_LAUNCHD_PLIST)

helper: $(HELPER_LABEL)

$(HELPER_INFO_PLIST): $(HELPER_INFO_TEMPLATE)
	@echo Generating $@
	sed -e 's/_VERSION_/$(HELPER_VERSION)/g' -e 's/_TEAMID_/$(VC_OSX_TEAM_ID)/g' $< > $@

$(HELPER_LAUNCHD_PLIST): $(HELPER_LAUNCHD_TEMPLATE)
	@echo Generating $@
	sed -e 's/_VERSION_/$(HELPER_VERSION)/g' -e 's/_TEAMID_/$(VC_OSX_TEAM_ID)/g' $< > $@

Helper.o: Helper.cpp
	@echo Compiling Helper.cpp
	$(CXX) $(CXXFLAGS) -fblocks -c $< -o $@

$(HELPER_LABEL): Helper.o $(HELPER_INFO_PLIST) $(HELPER_LAUNCHD_PLIST)
	@echo Linking $@
	$(CXX) $(LFLAGS) -fblocks \
		-framework Security -framework ServiceManagement -framework CoreFoundation \
		-Wl,-sectcreate,__TEXT,__info_plist,$(HELPER_INFO_PLIST) \
		-Wl,-sectcreate,__TEXT,__launchd_plist,$(HELPER_LAUNCHD_PLIST) \
		-o $@ Helper.o

clean:
	@echo Cleaning PrivilegedHelper
	rm -f Helper.o Helper.d $(HELPER_LABEL) $(HELPER_INFO_PLIST) $(HELPER_LAUNCHD_PLIST)
