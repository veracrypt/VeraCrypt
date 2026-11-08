VERSION_FILE := ../../../Common/Tcdefs.h
PKGBUILD_RELEASE := PKGBUILD.release
PKGBUILD_RELEASE_TEMPLATE := PKGBUILD.release.in

.PHONY: pkgbuild-release
pkgbuild-release: $(PKGBUILD_RELEASE)

$(PKGBUILD_RELEASE): $(PKGBUILD_RELEASE_TEMPLATE) $(VERSION_FILE)
	@version="$$(awk -F '"' '/^[[:space:]]*#define[[:space:]]+VERSION_STRING[[:space:]]*"/ { print $$2; exit }' "$(VERSION_FILE)")"; \
	if [ -z "$$version" ]; then \
		echo "Unable to read VERSION_STRING from $(VERSION_FILE)" >&2; \
		exit 1; \
	fi; \
	{ \
		printf '%s\n' '# Maintainer: VeraCrypt upstream'; \
		printf '%s\n' '# DO NOT EDIT: generated from PKGBUILD.release.in by `make pkgbuild-release`.'; \
		sed -e '1,2d' -e "s/@VERSION@/$$version/g" "$(PKGBUILD_RELEASE_TEMPLATE)"; \
	} > "$(PKGBUILD_RELEASE)"

.PHONY: clean
clean:
	@if [ -d pkg ]; then rm -rf -- pkg; fi
	@if [ -d src ]; then rm -rf -- src; fi
	rm -f -- $(PKGBUILD_RELEASE) *.pkg.tar* *.log
