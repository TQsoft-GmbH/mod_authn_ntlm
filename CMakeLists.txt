#
# -- CMAKE build file for mod_auth_ntlm
#
cmake_minimum_required (VERSION 3.9.1)
project(mod_authn_ntlm C)
set(LIBAPR "libapr-1")
set(LIBAPRUTIL "libaprutil-1")

if(NOT DEFINED APACHE_ROOT)
set(APACHE_ROOT "Apache24")
endif()
option( USE_STATIC_RUNTIME "use MSVC static runtimes" OFF)
#
# -- Windows option for static runtimes - must match Apache build
#    default is OFF and will use /MD /MDd, which links against VC runtime dlls.
#    USE_STATIC_RUNTIME uses /MT or /MTd, no VC dlls needed
#    
if(DEFINED USE_STATIC_RUNTIME AND USE_STATIC_RUNTIME AND WIN32)
   # Set MSVC runtime flags for all configurations
    foreach(cfg "" ${CMAKE_CONFIGURATION_TYPES})
        set(flag_var CMAKE_CXX_FLAGS)
        if(cfg)
            string(TOUPPER ${cfg} cfg_upper)
            string(APPEND flag_var "_${cfg_upper}")
        endif()
        if(${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif()
        set(flag_var CMAKE_C_FLAGS)
        if(cfg)
            string(TOUPPER ${cfg} cfg_upper)
            string(APPEND flag_var "_${cfg_upper}")
        endif()
        if(${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif()
    endforeach()
endif()

include_directories(${APACHE_ROOT}/include)
link_directories(${APACHE_ROOT}/lib)

file(GLOB_RECURSE SOURCE_FILES
    "src/*.h"
    "src/*.c"
)

add_library(mod_authn_ntlm SHARED ${SOURCE_FILES})
set_target_properties(mod_authn_ntlm PROPERTIES SUFFIX ".so")
target_link_libraries(mod_authn_ntlm libhttpd ${LIBAPR} ${LIBAPRUTIL})

install(TARGETS mod_authn_ntlm
        CONFIGURATIONS Release
        CONFIGURATIONS Debug
        RUNTIME DESTINATION ${APACHE_ROOT}/modules
)
