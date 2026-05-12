cmake_minimum_required(VERSION 3.20)
project(forensicator CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include(GNUInstallDirs)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ---- Dependencies ----
# Need SQLite >= 3.24 for INSERT ... ON CONFLICT ... DO UPDATE (UPSERT).
find_package(SQLite3 3.24 REQUIRED)
message(STATUS "Using SQLite3 ${SQLite3_VERSION}: ${SQLite3_INCLUDE_DIRS}")

# OpenSSL is optional; fall back to vendored SHA-512.
# Require >= 1.1 because we use EVP_MD_CTX_new / EVP_MD_CTX_free.
set(_have_openssl FALSE)
find_package(OpenSSL 1.1 COMPONENTS Crypto QUIET)
if(OpenSSL_FOUND AND TARGET OpenSSL::Crypto)
    set(_have_openssl TRUE)
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION} for SHA-512")
else()
    message(STATUS "OpenSSL >= 1.1 not found; using vendored SHA-512")
endif()

# Threads
find_package(Threads REQUIRED)

# ---- Library (object lib for code shared with tests) ----
set(_lib_sources
    src/catalog.cpp
    src/hashlog.cpp
    src/json.cpp
    src/pathnorm.cpp
    src/pipeline.cpp
    src/sha512.cpp
    src/util.cpp
    src/walker.cpp
    src/cmd_scan.cpp
    src/cmd_dedupe.cpp
    src/cmd_prune.cpp
    src/cmd_merge.cpp
)

add_library(forensicator_lib STATIC ${_lib_sources})
target_include_directories(forensicator_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(forensicator_lib PUBLIC
    FORENSICATOR_INSTALL_DATAROOT="${CMAKE_INSTALL_FULL_DATAROOTDIR}"
)
target_link_libraries(forensicator_lib PUBLIC
    SQLite::SQLite3
    Threads::Threads
)
if(_have_openssl)
    target_compile_definitions(forensicator_lib PUBLIC FORENSICATOR_USE_OPENSSL=1)
    target_link_libraries(forensicator_lib PUBLIC OpenSSL::Crypto)
    # Ensure OpenSSL headers are searched BEFORE other deps (some package
    # managers like MacPorts ship an old /opt/local/include/openssl that
    # would otherwise shadow the modern OpenSSL 1.1+/3.x we want).
    target_include_directories(forensicator_lib BEFORE PUBLIC ${OPENSSL_INCLUDE_DIR})
endif()

if(NOT MSVC)
    target_compile_options(forensicator_lib PRIVATE -Wall -Wextra -Wpedantic)
else()
    target_compile_options(forensicator_lib PRIVATE /W4 /permissive-)
endif()

# ---- Binary ----
add_executable(forensicator src/main.cpp)
target_link_libraries(forensicator PRIVATE forensicator_lib)

# ---- Install ----
install(TARGETS forensicator RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/../schema/forensicator.sql"
        DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/forensicator")

# ---- Tests ----
enable_testing()
add_subdirectory(tests)
