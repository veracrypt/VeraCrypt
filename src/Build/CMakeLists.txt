# - Minimum CMake version
cmake_minimum_required(VERSION 2.8.0)

# - Obligatory parameters
#		-DVERACRYPT_BUILD_DIR 	: folder that contains 'usr' folder
#		-DNOGUI					: TRUE if building 'Console' version, 'FALSE' if building 'GUI' version
if ( NOT DEFINED VERACRYPT_BUILD_DIR )
	MESSAGE(FATAL_ERROR "VERACRYPT_BUILD_DIR variable MUST BE set to the path of the folder which contains 'usr' folder")
elseif ( NOT DEFINED NOGUI )
	MESSAGE(FATAL_ERROR "NOGUI variable MUST BE set to TRUE if building 'Console' version, 'FALSE' otherwise")
endif()

# - Set PROJECT_NAME and CONFLICT_PACKAGE values
if (NOGUI)
	set( PROJECT_NAME 		"veracrypt-console" )
	set( CONFLICT_PACKAGE	"veracrypt" )
else()
	set( PROJECT_NAME 		"veracrypt" )
	set( CONFLICT_PACKAGE	"veracrypt-console" )
endif()
project(${PROJECT_NAME})

# - Check whether 'Tcdefs.h' and 'License.txt' exist
if(NOT EXISTS "$ENV{SOURCEPATH}/Common/Tcdefs.h")
	MESSAGE(FATAL_ERROR "Tcdefs.h does not exist.")
elseif(NOT EXISTS "$ENV{SOURCEPATH}/License.txt")
	MESSAGE(FATAL_ERROR "License.txt does not exist.")
endif()

# - Detect build system bitness
#	The following variable will be set
#		$SUFFIX					32			64
#		$CMAKE_SYSTEM_NAME		Windows		Linux	Darwin
# 	N.B : 
#		To build for 32-bit under 64-bit, set 'CMAKE_SIZEOF_VOID_P' to '4'
if( CMAKE_SIZEOF_VOID_P EQUAL 8 )

	#	Build System is under 64-bit arch
	set (SUFFIX "64")
	MESSAGE(STATUS "Build System = ${CMAKE_SYSTEM_NAME} - Bitness : 64-bit - Compiler : ${CMAKE_CXX_COMPILER_ID}")
	
elseif( CMAKE_SIZEOF_VOID_P EQUAL 4 )

	#	Build System is under 32-bit arch
	set (SUFFIX "32")
	MESSAGE(STATUS "Build System = ${CMAKE_SYSTEM_NAME} - Bitness : 32-bit - Compiler : ${CMAKE_CXX_COMPILER_ID}")
	
else( )

	MESSAGE(FATAL_ERROR "Could not detect system bitness")
	
endif( )

# - Detect OSX, CentOS, Debian, Ubuntu or openSUSE platform of the build system
#   The following variable(s) will be set
#   	$PLATFORM						Debian		Ubuntu 		CentOS		openSUSE 
#   	$PLATFORM_VERSION	
#										9.x 		16.04		7.X			42.3
#										10.X		18.04		8.X			15.0
# 		$DISTRO_NAME					${PLATFORM}-${PLATFORM_VERSION}
if ( UNIX )

	# /etc/debian_version exists for both Debian and Ubuntu
	if(EXISTS "/etc/debian_version")		
	
		set ( PLATFORM "Debian" )
	
		# Read lsb-release to get flavour name and flavour release version (only supported one for now is Ubuntu)
		if(EXISTS "/etc/lsb-release")		
		
			file(READ "/etc/lsb-release" LSB_RELEASE_ID)
			string(REGEX MATCH "DISTRIB_ID=([a-zA-Z0-9 /\\.]+)" _ ${LSB_RELEASE_ID})
			set(FULL_FLAVOUR ${CMAKE_MATCH_1})
			
			if (FULL_FLAVOUR MATCHES "^.*Ubuntu.*$")
			
				set ( PLATFORM "Ubuntu" )
			
				file(READ "/etc/lsb-release" UBUNTU_RELEASE)
				string(REGEX MATCH "DISTRIB_RELEASE=([0-9 /\\.]+)" _ ${UBUNTU_RELEASE})
				set(PLATFORM_VERSION ${CMAKE_MATCH_1})
				
			else()
			
				file(READ "/etc/debian_version" DEBIAN_RELEASE)
				string(REGEX MATCH "[a-zA-Z0-9 /\\.]+" _ ${DEBIAN_RELEASE})
				set(PLATFORM_VERSION ${CMAKE_MATCH_1})
				
				if( PLATFORM_VERSION STREQUAL "stretch/sid" )
					set( PLATFORM_VERSION "9" )
				endif( PLATFORM_VERSION STREQUAL "stretch/sid" )
				
			endif()
			
		# Get debian release version
		elseif(EXISTS "/etc/debian_version")
		
			file(READ "/etc/debian_version" DEBIAN_RELEASE)
			string(REGEX MATCH "[a-zA-Z0-9 /\\.]+" _ ${DEBIAN_RELEASE})
			set(PLATFORM_VERSION ${CMAKE_MATCH_1})
					
		endif()
	
	# Get centos release version
	elseif(EXISTS "/etc/centos-release")	
	
		set ( PLATFORM "CentOS" )
		
		file(READ "/etc/centos-release" CENTOS_RELEASE)
		string(REGEX MATCH "release ([0-9 /\\.]+)" _ ${CENTOS_RELEASE})
        set(PLATFORM_VERSION ${CMAKE_MATCH_1})
	
	# Only if distribution uses systemd and if all previous files didn't exist
	# i.e OpenSUSE
	elseif(EXISTS "/etc/os-release")	
	
		file(READ "/etc/os-release" OS_RELEASE_NAME)
		string(REGEX MATCH "NAME=\"([a-zA-Z0-9 /\\.]+)\"" _ ${OS_RELEASE_NAME})
		set(FULL_PLATFORM ${CMAKE_MATCH_1})
		
		if (FULL_PLATFORM MATCHES "^.*openSUSE.*$")
			set ( PLATFORM "openSUSE" )
		elseif ( FULL_PLATFORM MATCHES "^.*Ubuntu.*$")
			set ( PLATFORM "Ubuntu" )
		elseif ( FULL_PLATFORM MATCHES "^.*Debian.*$")
			set ( PLATFORM "Debian" )
		elseif ( FULL_PLATFORM MATCHES "^.*CentOS.*$" )
			set ( PLATFORM "CentOS" )
		endif ( )
		
		# Get ditribution release version
		file(READ "/etc/os-release" OS_RELEASE)
		string(REGEX MATCH "VERSION=\"([a-zA-Z0-9 /\\.]+)\"" _ ${OS_RELEASE})
		set(PLATFORM_VERSION ${CMAKE_MATCH_1})
		
	endif()

endif ( )
string(REGEX REPLACE " $" "" PLATFORM_VERSION "${PLATFORM_VERSION}")	# Trim the last trailing whitespace
set ( DISTRO_NAME ${PLATFORM}-${PLATFORM_VERSION} )
MESSAGE ( STATUS "Platform = ${PLATFORM}" )
MESSAGE ( STATUS "Platform Version = ${PLATFORM_VERSION}" )
MESSAGE ( STATUS "Distribution name = ${DISTRO_NAME}" )

# - Detect the architecture under OSX, Debian, CentOS and OpenSUSE platforms
#	The following variable will be set
#		$ARCHITECTURE
if ( PLATFORM STREQUAL "Debian" OR PLATFORM STREQUAL "Ubuntu" )

	# There is no such thing as i686 architecture on debian, i386 is to be used instead
	# dpkg --print-architecture
	find_program(DPKG_CMD dpkg)
	if(NOT DPKG_CMD)
		# Cannot find dpkg in path
		# Try best guess following SUFFIX value calculated from CMAKE_SIZEOF_VOID_P
		if (SUFFIX STREQUAL "32")
			SET(ARCHITECTURE i386)
		elseif (SUFFIX STREQUAL "64")
			SET(ARCHITECTURE amd64)
		endif()
	else(NOT DPKG_CMD)
		execute_process(COMMAND dpkg --print-architecture OUTPUT_VARIABLE ARCHITECTURE OUTPUT_STRIP_TRAILING_WHITESPACE)
	endif(NOT DPKG_CMD)
	
elseif ( ( PLATFORM STREQUAL "CentOS" ) OR ( PLATFORM STREQUAL "openSUSE" ) )

	execute_process(COMMAND arch OUTPUT_VARIABLE ARCHITECTURE OUTPUT_STRIP_TRAILING_WHITESPACE)
	
elseif ( PLATFORM STREQUAL "OSX" )

	if ( UNIVERSAL )
		set ( ARCHITECTURE "Univesal-Binary" )
	else ( UNIVERSAL )
		# arch reports Intel using the i386 label rather than intel
		# We use uname -m instead
		execute_process(COMMAND uname -m OUTPUT_VARIABLE ARCHITECTURE OUTPUT_STRIP_TRAILING_WHITESPACE)
	endif( UNIVERSAL )
	
endif ( )
MESSAGE ( STATUS "Architecture = ${ARCHITECTURE}" )

# - Create installation folder directory at install time
#	This won't lead to the files being actually installed (in CMAKE_INSTALL_PREFIX)
#	unless "cmake --build . --target install" is executed, which is not the case here/
# 	
#	Doing things like the following
#		-	install(DIRECTORY 	${VERACRYPT_BUILD_DIR}/usr DESTINATION /)
#		-	install(DIRECTORY 	${VERACRYPT_BUILD_DIR}/usr/bin DESTINATION /usr)
#	lead to conflicts despite the usage of CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
#	because install() forces CpackRPM to create the DESTINATION folders.
#
#	We fix this by installing ALL directories inside '/usr' in '.', and setting 
#	CPACK_PACKAGING_INSTALL_PREFIX to '/usr'.
#	This way, during the packaging, 'bin' and 'share' folders will be installed 
#	inside '${CPACK_PACKAGE_DIRECTORY}/_CPack_Packages/<system_name>/DEB,RPM/${CPACK_PACKAGE_NAME}/${CPACK_PACKAGING_INSTALL_PREFIX}'.
#
#	Also, we use USE_SOURCE_PERMISSIONS to save the permissions
install(DIRECTORY 	${VERACRYPT_BUILD_DIR}/usr/bin
		DESTINATION .
		USE_SOURCE_PERMISSIONS)
install(DIRECTORY 	${VERACRYPT_BUILD_DIR}/usr/share
		DESTINATION .
		USE_SOURCE_PERMISSIONS)
set(CPACK_PACKAGING_INSTALL_PREFIX "/usr")

# For packaging 
# CPack will first install into ${CPACK_PACKAGE_DIRECTORY}/_CPack_Packages/<system_name>/DEB,RPM/${CPACK_PACKAGE_NAME}/${CPACK_PACKAGING_INSTALL_PREFIX}
# See https://gitlab.kitware.com/cmake/community/wikis/doc/cpack/PackageGenerators
# See https://cmake.org/cmake/help/latest/cpack_gen/deb.html
# See https://cmake.org/cmake/help/latest/cpack_gen/rpm.html
#

# Installation scripts should be provided in this order
# 	PREINST;POSTINST;PRERM;POSTRM

file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/Packaging)	# creates the Packaging directory under build directory when CMake generates the build system

# - We excute 'grep VERSION_STRING ../../Common/Tcdefs.h | head -n 1' to get the line which include 'VERSION_STRING'
#	Then we delete all first characters from the beginning of the line until the first '"' to get the version in the format : "X.YYY..."
#	Then, we remove the leading and trailing '"' characters
#	Then, we retrieve the 'version' and the 'release'
#	Finally, we replace '-' in the release if it exists with a '.' because CPack does not like '-' in the release
execute_process(COMMAND grep VERSION_STRING "$ENV{SOURCEPATH}/Common/Tcdefs.h"
				COMMAND head -n 1
				OUTPUT_VARIABLE FULL_VERSION_LINE OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REGEX REPLACE "^[^\"]+" "" FULL_VERSION ${FULL_VERSION_LINE})
string(REGEX REPLACE "\"" "" FULL_VERSION ${FULL_VERSION})
string(REPLACE "." ";" FULL_VERSION_LIST ${FULL_VERSION})
list(GET FULL_VERSION_LIST 0 VERSION)
list(GET FULL_VERSION_LIST 1 RELEASE)
string(REPLACE "-" "." RELEASE ${RELEASE})

set( VENDOR "IDRIX" )
set( LICENSE "VeraCrypt License" )
set( CONTACT "VeraCrypt Team <veracrypt@idrix.fr>" )
set( CPACK_PACKAGE_DESCRIPTION_SUMMARY "Disk encryption with strong security based on TrueCrypt." )
set( CPACK_PACKAGE_DESCRIPTION "This package contains binaries for VeraCrypt, a disk encryption with strong security based on TrueCrypt." )
set( CPACK_PACKAGE_NAME 			${PROJECT_NAME} )
set( CPACK_PACKAGE_VERSION 			${VERSION} )
set( CPACK_PACKAGE_RELEASE 			${RELEASE} )
set( CPACK_PACKAGE_VENDOR 			${VENDOR} )
set( CPACK_PACKAGE_LICENSE 			${LICENSE} )
set( CPACK_RESOURCE_FILE_LICENSE 	"$ENV{SOURCEPATH}/License.txt")
set( CPACK_PACKAGE_CONTACT 			${CONTACT} )	
set( CPACK_PACKAGE_FILE_NAME 		${CPACK_PACKAGE_NAME}-${FULL_VERSION}-${DISTRO_NAME}-${ARCHITECTURE} )
set( CPACK_PACKAGE_CHECKSUM 		SHA256 )
set( CPACK_PACKAGE_RELOCATABLE 		"OFF")																						# Disable package relocation (especially for rpm)
set( CPACK_PACKAGE_DIRECTORY 		${CMAKE_CURRENT_BINARY_DIR}/Packaging )

if ( ( PLATFORM STREQUAL "Debian" ) OR ( PLATFORM STREQUAL "Ubuntu" ) )
	
	# Debian control script(s)
	file( MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/Packaging/debian-control)
	configure_file(		${CMAKE_CURRENT_SOURCE_DIR}/Packaging/debian-control/prerm 		${CMAKE_CURRENT_BINARY_DIR}/Packaging/debian-control/prerm)
	set( DEBIAN_PRERM 	${CMAKE_CURRENT_BINARY_DIR}/Packaging/debian-control/prerm)
	
	set( CPACK_GENERATOR 					"DEB" )																				# mandatory
	set( CPACK_DEBIAN_PACKAGE_NAME 			${CPACK_PACKAGE_NAME}  )															# mandatory
	set( CPACK_DEBIAN_FILE_NAME 			${CPACK_PACKAGE_FILE_NAME}.deb )													# mandatory
	set( CPACK_DEBIAN_PACKAGE_VERSION 		${CPACK_PACKAGE_VERSION} )															# mandatory
	set( CPACK_DEBIAN_PACKAGE_RELEASE 		${CPACK_PACKAGE_RELEASE} )
	set( CPACK_DEBIAN_PACKAGE_ARCHITECTURE 	${ARCHITECTURE} )																	# mandatory
	
	set( CPACK_DEBIAN_PACKAGE_DEPENDS 		"libwxgtk3.0-0v5, libfuse2, dmsetup")
		
	set( CPACK_DEBIAN_PACKAGE_MAINTAINER 	${CONTACT} )																		# mandatory
	set( CPACK_DEBIAN_PACKAGE_DESCRIPTION 	${CPACK_PACKAGE_DESCRIPTION_SUMMARY} )												# mandatory
	set( CPACK_DEBIAN_ARCHIVE_TYPE 			"gnutar")																			# mandatory
	set( CPACK_DEBIAN_COMPRESSION_TYPE 		"gzip")																				# mandatory
	set( CPACK_DEBIAN_PACKAGE_PRIORITY 		"optional" )																		# mandatory
	set( CPACK_DEBIAN_PACKAGE_SECTION 		"libs" )		 																	# recommended, to do, Section relative to Debian sections (https://www.debian.org/doc/debian-policy/ch-archive.html#s-subsections)
	set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA 	${DEBIAN_PREINST};${DEBIAN_POSTINST};${DEBIAN_PRERM};${DEBIAN_POSTRM})
	set(CPACK_DEBIAN_PACKAGE_CONFLICTS 		${CONFLICT_PACKAGE})
	
elseif ( ( PLATFORM STREQUAL "CentOS" ) OR ( PLATFORM STREQUAL "openSUSE" ) )
	
	# RPM control script(s)
	file( MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/Packaging/rpm-control)
	configure_file(	${CMAKE_CURRENT_SOURCE_DIR}/Packaging/rpm-control/prerm.sh 		${CMAKE_CURRENT_BINARY_DIR}/Packaging/rpm-control/prerm.sh)
	set( RPM_PRERM 	${CMAKE_CURRENT_BINARY_DIR}/Packaging/rpm-control/prerm.sh)
	
	set( CPACK_GENERATOR 				"RPM" )																					# mandatory
	set( CPACK_RPM_PACKAGE_SUMMARY 		${CPACK_PACKAGE_SUMMARY} )																# mandatory
	set( CPACK_RPM_PACKAGE_DESCRIPTION 	${CPACK_PACKAGE_DESCRIPTION} )															# mandatory
	set( CPACK_RPM_PACKAGE_NAME 		${CPACK_PACKAGE_NAME} )																	# mandatory
	set( CPACK_RPM_FILE_NAME 			${CPACK_PACKAGE_FILE_NAME}.rpm )														# mandatory
	set( CPACK_RPM_PACKAGE_VERSION 		${CPACK_PACKAGE_VERSION} )																# mandatory
	set( CPACK_RPM_PACKAGE_ARCHITECTURE ${ARCHITECTURE} )																		# mandatory
	set( CPACK_RPM_PACKAGE_RELEASE 		${CPACK_PACKAGE_RELEASE} )																# mandatory
	set( CPACK_RPM_PACKAGE_LICENSE 		${CPACK_PACKAGE_LICENSE} )																# mandatory 
	set( CPACK_RPM_PACKAGE_GROUP 		"Applications/System" )																	# mandatory, https://fedoraproject.org/wiki/RPMGroups
	set( CPACK_RPM_PACKAGE_VENDOR 		${CPACK_PACKAGE_VENDOR} )																# mandatory
	set( CPACK_RPM_PACKAGE_AUTOREQ 		"no" ) 																					# disable automatic shared libraries dependency detection (most of the time buggy)
	
	if ( PLATFORM STREQUAL "CentOS" )
		set( CPACK_RPM_PACKAGE_REQUIRES 	"fuse, device-mapper, gtk3")
	elseif ( PLATFORM STREQUAL "openSUSE" )
		#	TODO
	endif()
	
	set( CPACK_RPM_PRE_UNINSTALL_SCRIPT_FILE 			${RPM_PRERM})															# optional
	
	# Prevents CPack from generating file conflicts
	# This is to avoid having %dir of these directories in the .spec file
	set( CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION 			"/usr" )
	list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION	"/usr/bin" )
	list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION	"/usr/share" )
	list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION	"/usr/share/applications" )
	list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION	"/usr/share/doc" )
	list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION	"/usr/share/pixmaps" )
	
	set( CPACK_RPM_PACKAGE_RELOCATABLE 					"OFF" )
	set( CPACK_RPM_PACKAGE_CONFLICTS 					"${CONFLICT_PACKAGE}")
	
endif()

include(CPack)
