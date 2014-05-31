# Test executables
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS}")

#Verbose
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs_test REQUIRED)
FOREACH(flag ${pkgs_test_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")

ADD_EXECUTABLE(pkgmgr_tool main.c)
TARGET_LINK_LIBRARIES(pkgmgr_tool capi-appfw-package-manager ${pkgs_test_LDFLAGS})
INSTALL(TARGETS pkgmgr_tool DESTINATION bin)

