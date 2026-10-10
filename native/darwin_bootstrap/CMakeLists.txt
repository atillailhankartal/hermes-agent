cmake_minimum_required(VERSION 3.20)
project(bee_hermes_darwin_bootstrap C)

if(NOT APPLE)
  message(FATAL_ERROR "Darwin bootstrap requires the pinned macOS SDK")
endif()

add_library(bee_hermes_a2a STATIC
  launch_authority.c
  stage0.c
  release_manifest.c
  fd_inventory.c
  socket_lineage.c
  ../trusted_inbound/darwin/socket_observer.c)
target_compile_features(bee_hermes_a2a PRIVATE c_std_11)
target_compile_options(bee_hermes_a2a PRIVATE -Wall -Wextra -Werror -pedantic)
target_include_directories(bee_hermes_a2a PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# No install, service, CLI, Gateway, TUI or key/source admission target exists here.

# Independent dormant metadata helper; deliberately not linked into A2a or a host.
add_library(bee_hermes_a2b_fd7 STATIC broker_entry.c)
target_compile_features(bee_hermes_a2b_fd7 PRIVATE c_std_11)
target_compile_options(bee_hermes_a2b_fd7 PRIVATE -Wall -Wextra -Werror -pedantic)
target_include_directories(bee_hermes_a2b_fd7 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
