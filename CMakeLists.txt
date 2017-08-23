cmake_minimum_required (VERSION 3.9.1)

project(mod_authn_ntlm C)

set(LIBAPR "libapr-1")
set(LIBAPRUTIL "libaprutil-1")

if (MSVC)
	if(CMAKE_BUILD_TYPE MATCHES Debug)
		add_definitions(/MTd)
	else()
		add_definitions(/MT)
	endif()
endif()

include_directories(Apache24/include)
LINK_DIRECTORIES(Apache24/lib)



file(GLOB_RECURSE SOURCE_FILES

    "src/*.h"

    "src/*.c"

)



add_library(mod_authn_ntlm SHARED ${SOURCE_FILES})
target_link_libraries(mod_authn_ntlm libhttpd ${LIBAPR} ${LIBAPRUTIL})