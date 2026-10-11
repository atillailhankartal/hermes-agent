cmake_minimum_required(VERSION 3.20)
project(bee_hermes_darwin_bootstrap C)

if(NOT APPLE)
  message(FATAL_ERROR "Darwin bootstrap requires the pinned macOS SDK")
endif()

# Explicit structure-only v2 parser exercise. Neither target is in the default
# build, installed, nor linked into a launcher, host, broker or Hermes client.
option(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_TESTS
  "Explicit dormant signed-preflight v2 structure tests" OFF)
if(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_TESTS)
  add_library(bee_hermes_signed_preflight_v2 STATIC EXCLUDE_FROM_ALL
    signed_preflight_v2.c)
  add_executable(bee_hermes_signed_preflight_v2_test EXCLUDE_FROM_ALL
    ../../tests/native/darwin_bootstrap/test_signed_preflight_v2.c)
  target_compile_features(bee_hermes_signed_preflight_v2 PRIVATE c_std_11)
  target_compile_features(bee_hermes_signed_preflight_v2_test PRIVATE c_std_11)
  target_compile_options(bee_hermes_signed_preflight_v2 PRIVATE
    -Wall -Wextra -Werror -pedantic)
  target_compile_options(bee_hermes_signed_preflight_v2_test PRIVATE
    -Wall -Wextra -Werror -pedantic)
  target_include_directories(bee_hermes_signed_preflight_v2 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(bee_hermes_signed_preflight_v2_test PRIVATE
    bee_hermes_signed_preflight_v2)
endif()

# Explicit cryptographic-consistency exercise using a caller-supplied public
# key. OFF, excluded from ALL, and never linked into an installed image.
option(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_CRYPTO_TESTS
  "Explicit dormant signed-preflight v2 crypto tests" OFF)
if(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_CRYPTO_TESTS)
  add_library(bee_hermes_signed_preflight_v2_crypto STATIC EXCLUDE_FROM_ALL
    signed_preflight_v2_crypto.c signed_preflight_v2.c)
  add_executable(bee_hermes_signed_preflight_v2_crypto_test EXCLUDE_FROM_ALL
    ../../tests/native/darwin_bootstrap/test_signed_preflight_v2_crypto.c)
  foreach(crypto_target bee_hermes_signed_preflight_v2_crypto
          bee_hermes_signed_preflight_v2_crypto_test)
    target_compile_features(${crypto_target} PRIVATE c_std_11)
    target_compile_options(${crypto_target} PRIVATE
      -Wall -Wextra -Werror -pedantic)
    target_include_directories(${crypto_target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  endforeach()
  target_link_libraries(bee_hermes_signed_preflight_v2_crypto PRIVATE
    "-framework Security" "-framework CoreFoundation")
  target_link_libraries(bee_hermes_signed_preflight_v2_crypto_test PRIVATE
    bee_hermes_signed_preflight_v2_crypto)
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

# Phase-1 mechanics executable only; no install or broker admission target.
add_library(bee_hermes_a2c_phase1 STATIC a2c_policy.c launch_control.c)
target_compile_features(bee_hermes_a2c_phase1 PRIVATE c_std_11)
target_compile_options(bee_hermes_a2c_phase1 PRIVATE -Wall -Wextra -Werror -pedantic)
target_link_libraries(bee_hermes_a2c_phase1 PUBLIC bee_hermes_a2a)
add_executable(bee_hermes_a2c_attempt attempt_entry.c)
target_compile_features(bee_hermes_a2c_attempt PRIVATE c_std_11)
target_compile_options(bee_hermes_a2c_attempt PRIVATE -Wall -Wextra -Werror -pedantic)
target_link_libraries(bee_hermes_a2c_attempt PRIVATE bee_hermes_a2c_phase1)

# Separate dormant images. No installed identity policy or test drop adapter here.
add_executable(bee_hermes_a2c_final final_entry.c)
add_executable(bee_hermes_a2c_stage0 stage0_entry.c)
foreach(image bee_hermes_a2c_final bee_hermes_a2c_stage0)
  target_compile_features(${image} PRIVATE c_std_11)
  target_compile_options(${image} PRIVATE -Wall -Wextra -Werror -pedantic)
  target_link_libraries(${image} PRIVATE bee_hermes_a2c_phase1)
endforeach()
target_compile_definitions(bee_hermes_a2c_stage0 PRIVATE
  BH_A2C_FINAL_IMAGE="$<TARGET_FILE:bee_hermes_a2c_final>")
add_dependencies(bee_hermes_a2c_stage0 bee_hermes_a2c_final)
add_executable(bee_hermes_a2c_phase2_attempt attempt_entry.c launch_control.c a2c_policy.c)
target_compile_features(bee_hermes_a2c_phase2_attempt PRIVATE c_std_11)
target_compile_options(bee_hermes_a2c_phase2_attempt PRIVATE -Wall -Wextra -Werror -pedantic)
target_compile_definitions(bee_hermes_a2c_phase2_attempt PRIVATE BH_A2C_PHASE2
  BH_A2C_STAGE0_IMAGE="$<TARGET_FILE:bee_hermes_a2c_stage0>")
target_link_libraries(bee_hermes_a2c_phase2_attempt PRIVATE bee_hermes_a2a)
add_dependencies(bee_hermes_a2c_phase2_attempt bee_hermes_a2c_stage0)

# Source mechanics only. These exact uninstalled images have no policy provider
# that can authorize a launch. Fixture providers are never part of this graph.
add_executable(bee_hermes_a2c_phase3_final final_entry.c
  a2c_phase3_policy.c a2c_phase3_io.c a2c_phase3_unavailable.c)
add_executable(bee_hermes_a2c_phase3_stage0 stage0_entry.c)
target_link_libraries(bee_hermes_a2c_phase3_stage0 PRIVATE bee_hermes_a2c_phase1)
target_link_options(bee_hermes_a2c_phase3_stage0 PRIVATE
  "LINKER:-map,${CMAKE_CURRENT_BINARY_DIR}/bee_hermes_a2c_phase3_stage0.map")
target_compile_definitions(bee_hermes_a2c_phase3_stage0 PRIVATE
  BH_A2C_FINAL_IMAGE="$<TARGET_FILE:bee_hermes_a2c_phase3_final>")
add_dependencies(bee_hermes_a2c_phase3_stage0 bee_hermes_a2c_phase3_final)
add_executable(bee_hermes_a2c_phase3_attempt attempt_entry.c launch_control.c a2c_policy.c
  a2c_phase3_policy.c a2c_phase3_journal.c a2c_phase3_io.c a2c_phase3_unavailable.c)
foreach(image bee_hermes_a2c_phase3_attempt bee_hermes_a2c_phase3_final)
  target_compile_definitions(${image} PRIVATE BH_A2C_PHASE3
    BH_A2C_STAGE0_IMAGE="$<TARGET_FILE:bee_hermes_a2c_phase3_stage0>")
  target_link_options(${image} PRIVATE "LINKER:-map,${CMAKE_CURRENT_BINARY_DIR}/${image}.map")
endforeach()
target_link_libraries(bee_hermes_a2c_phase3_attempt PRIVATE bee_hermes_a2a)
target_link_libraries(bee_hermes_a2c_phase3_final PRIVATE bee_hermes_a2c_phase1)
# F has no orchestration or parent manifest: compile control helpers separately
# without the Phase3 orchestration definition.
foreach(image bee_hermes_a2c_phase3_attempt bee_hermes_a2c_phase3_final bee_hermes_a2c_phase3_stage0)
  target_compile_features(${image} PRIVATE c_std_11)
  target_compile_options(${image} PRIVATE -Wall -Wextra -Werror -pedantic)
endforeach()
add_dependencies(bee_hermes_a2c_phase3_attempt bee_hermes_a2c_phase3_stage0)

# Inert install preflight source exercise. There is no installed policy provider.
# The synthetic observation adapter exists only in the separate test image.
add_executable(hermes_bee_install_preflight
  install_preflight_main.c install_preflight.c install_preflight_unavailable.c)
add_executable(bee_hermes_install_preflight_test
  ../../tests/native/darwin_bootstrap/test_install_preflight.c
  ../../tests/native/darwin_bootstrap/test_install_preflight_adapter.c
  install_preflight.c install_preflight_unavailable.c)
foreach(image hermes_bee_install_preflight bee_hermes_install_preflight_test)
  target_compile_features(${image} PRIVATE c_std_11)
  target_compile_options(${image} PRIVATE -Wall -Wextra -Werror -pedantic)
  target_link_options(${image} PRIVATE "LINKER:-map,${CMAKE_CURRENT_BINARY_DIR}/${image}.map")
endforeach()

# Dormant diagnostic observer. The shared decision object is compiled once and
# is linked to distinct real and injected syscall adapters only in explicit tests.
# No observer target participates in the default build or an installed product.
option(BH_BUILD_DORMANT_PATH_OBSERVER_TESTS "Explicit dormant observer tests" OFF)
if(BH_BUILD_DORMANT_PATH_OBSERVER_TESTS)
  add_library(bee_hermes_path_observer_v1_core OBJECT EXCLUDE_FROM_ALL
    path_observer_core_v1.c)
  add_library(bee_hermes_path_observer_v1 STATIC EXCLUDE_FROM_ALL
    $<TARGET_OBJECTS:bee_hermes_path_observer_v1_core>
    path_observer_os_darwin_v1.c)
  add_executable(bee_hermes_path_observer_v1_real_test EXCLUDE_FROM_ALL
    ../../tests/native/darwin_bootstrap/test_path_observer_real.c)
  target_link_libraries(bee_hermes_path_observer_v1_real_test PRIVATE
    bee_hermes_path_observer_v1)
  add_executable(bee_hermes_path_observer_v1_injected_test EXCLUDE_FROM_ALL
    ../../tests/native/darwin_bootstrap/test_path_observer_injected.c
    ../../tests/native/darwin_bootstrap/path_observer_os_test_v1.c
    $<TARGET_OBJECTS:bee_hermes_path_observer_v1_core>)
  foreach(observer_target bee_hermes_path_observer_v1_core
          bee_hermes_path_observer_v1
          bee_hermes_path_observer_v1_real_test
          bee_hermes_path_observer_v1_injected_test)
    target_compile_features(${observer_target} PRIVATE c_std_11)
    target_compile_options(${observer_target} PRIVATE -Wall -Wextra -Werror -pedantic)
    target_include_directories(${observer_target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TARGET ${observer_target} PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
  endforeach()
  foreach(observer_image bee_hermes_path_observer_v1_real_test
          bee_hermes_path_observer_v1_injected_test)
    target_link_options(${observer_image} PRIVATE
      "LINKER:-map,${CMAKE_CURRENT_BINARY_DIR}/${observer_image}.map")
  endforeach()
endif()

# Dormant byte observation only: no authority and no installed consumers.
# The deterministic empty-ACL adapter is exclusively linked into the test image.
option(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_BUNDLE_TESTS
  "Explicit dormant signed-preflight v2 bundle observation tests" OFF)
if(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_BUNDLE_TESTS)
  add_library(bee_hermes_signed_preflight_v2_bundle_core OBJECT EXCLUDE_FROM_ALL
    signed_preflight_v2_bundle_reader.c)
  add_library(bee_hermes_signed_preflight_v2_bundle STATIC EXCLUDE_FROM_ALL
    $<TARGET_OBJECTS:bee_hermes_signed_preflight_v2_bundle_core>
    bundle_reader_os_darwin.c)
  add_executable(bee_hermes_signed_preflight_v2_bundle_test EXCLUDE_FROM_ALL
    ../../tests/native/darwin_bootstrap/test_signed_preflight_v2_bundle_reader.c
    ../../tests/native/darwin_bootstrap/bundle_reader_os_test.c
    $<TARGET_OBJECTS:bee_hermes_signed_preflight_v2_bundle_core>
    signed_preflight_v2.c signed_preflight_v2_crypto.c)
  foreach(bundle_target bee_hermes_signed_preflight_v2_bundle_core
          bee_hermes_signed_preflight_v2_bundle
          bee_hermes_signed_preflight_v2_bundle_test)
    target_compile_features(${bundle_target} PRIVATE c_std_11)
    target_compile_options(${bundle_target} PRIVATE -Wall -Wextra -Werror -pedantic)
    target_include_directories(${bundle_target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TARGET ${bundle_target} PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
  endforeach()
  target_compile_definitions(bee_hermes_signed_preflight_v2_bundle_test PRIVATE
    BH_BUNDLE_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/../../tests/native/darwin_bootstrap/fixtures/signed_preflight_v2"
    BH_BUNDLE_PREFLIGHT="$<TARGET_FILE:hermes_bee_install_preflight>")
  target_link_libraries(bee_hermes_signed_preflight_v2_bundle_test PRIVATE
    "-framework Security" "-framework CoreFoundation")
  target_link_options(bee_hermes_signed_preflight_v2_bundle_test PRIVATE
    "LINKER:-map,${CMAKE_CURRENT_BINARY_DIR}/bee_hermes_signed_preflight_v2_bundle_test.map")
  add_dependencies(bee_hermes_signed_preflight_v2_bundle_test
    hermes_bee_install_preflight bee_hermes_signed_preflight_v2_bundle)
endif()

# Stateless consistency only; no installed/default consumer or registration.
option(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_KEY_POLICY_TESTS
  "Explicit dormant signed-preflight v2 key-policy tests" OFF)
if(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_KEY_POLICY_TESTS)
  add_library(bee_hermes_signed_preflight_v2_key_policy STATIC EXCLUDE_FROM_ALL
    signed_preflight_v2_key_policy.c)
  add_executable(bee_hermes_signed_preflight_v2_key_policy_test EXCLUDE_FROM_ALL
    ../../tests/native/darwin_bootstrap/test_signed_preflight_v2_key_policy.c
    signed_preflight_v2_key_policy.c signed_preflight_v2.c signed_preflight_v2_crypto.c)
  foreach(key_policy_target bee_hermes_signed_preflight_v2_key_policy
          bee_hermes_signed_preflight_v2_key_policy_test)
    target_compile_features(${key_policy_target} PRIVATE c_std_11)
    target_compile_options(${key_policy_target} PRIVATE -Wall -Wextra -Werror -pedantic)
    target_include_directories(${key_policy_target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    set_property(TARGET ${key_policy_target} PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
  endforeach()
  target_compile_definitions(bee_hermes_signed_preflight_v2_key_policy_test PRIVATE
    BH_KEY_POLICY_TESTING)
  target_link_libraries(bee_hermes_signed_preflight_v2_key_policy_test PRIVATE
    "-framework Security" "-framework CoreFoundation")
  target_link_options(bee_hermes_signed_preflight_v2_key_policy_test PRIVATE
    "LINKER:-map,${CMAKE_CURRENT_BINARY_DIR}/bee_hermes_signed_preflight_v2_key_policy_test.map")
endif()

# Pure dormant journal byte/consistency codec. No installed or default consumer.
option(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_JOURNAL_TESTS
  "Explicit dormant signed-preflight v2 journal codec tests" OFF)
if(BH_BUILD_DORMANT_SIGNED_PREFLIGHT_V2_JOURNAL_TESTS)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  set(journal_fixture_dir "${CMAKE_CURRENT_SOURCE_DIR}/../../tests/native/darwin_bootstrap/fixtures/signed_preflight_v2_journal")
  add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/journal_vectors.h"
    COMMAND "${Python3_EXECUTABLE}" "${journal_fixture_dir}/run.py"
      --emit-header "${CMAKE_CURRENT_BINARY_DIR}/journal_vectors.h"
    DEPENDS "${journal_fixture_dir}/run.py" "${journal_fixture_dir}/golden-vectors.json"
    VERBATIM)
  add_library(bee_hermes_signed_preflight_v2_journal STATIC EXCLUDE_FROM_ALL
    signed_preflight_v2_journal_codec.c)
  add_executable(bee_hermes_signed_preflight_v2_journal_test EXCLUDE_FROM_ALL
    ../../tests/native/darwin_bootstrap/test_signed_preflight_v2_journal_codec.c
    "${CMAKE_CURRENT_BINARY_DIR}/journal_vectors.h")
  foreach(journal_target bee_hermes_signed_preflight_v2_journal
          bee_hermes_signed_preflight_v2_journal_test)
    target_compile_features(${journal_target} PRIVATE c_std_11)
    target_compile_options(${journal_target} PRIVATE -Wall -Wextra -Werror -pedantic)
    target_include_directories(${journal_target} PRIVATE
      "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}")
  endforeach()
  target_link_libraries(bee_hermes_signed_preflight_v2_journal_test PRIVATE
    bee_hermes_signed_preflight_v2_journal)
endif()
