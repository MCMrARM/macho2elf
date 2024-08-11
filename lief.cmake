cmake_minimum_required(VERSION 3.11)

# URL of the LIEF repo (Can be your fork)
set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

# LIEF's version to be used (can be 'master')
set(LIEF_VERSION 0.12.0)

# LIEF cmake options
option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Build LIEF tests" OFF)


include(FetchContent)
FetchContent_Declare(LIEF
      GIT_REPOSITORY  "${LIEF_GIT_URL}"
      GIT_TAG         ${LIEF_VERSION}
      # You may specify an existing LIEF source directory if you don't want to
      # download. Just comment out the above ``GIT_*`` commands and uncoment the
      # following ``SOURCE_DIR`` line
      #SOURCE_DIR      "${CMAKE_CURRENT_LIST_DIR}/../../.."
      )

if(${CMAKE_VERSION} VERSION_LESS "3.14.0")
  # CMake 3.11 to 3.13 needs more verbose method to make LIEF available
  FetchContent_GetProperties(LIEF)
  if(NOT LIEF_POPULATED)
      FetchContent_Populate(LIEF)
      add_subdirectory(${LIEF_SOURCE_DIR} ${LIEF_BINARY_DIR})
  endif()
else()
  # CMake 3.14+ has single function to make LIEF available (recommended)
  FetchContent_MakeAvailable(LIEF)
endif()
