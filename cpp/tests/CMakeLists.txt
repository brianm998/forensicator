add_executable(test_pathnorm test_pathnorm.cpp)
target_link_libraries(test_pathnorm PRIVATE forensicator_lib)
add_test(NAME test_pathnorm COMMAND test_pathnorm)

add_executable(test_catalog test_catalog.cpp)
target_link_libraries(test_catalog PRIVATE forensicator_lib)
add_test(NAME test_catalog COMMAND test_catalog)
set_tests_properties(test_catalog PROPERTIES
    ENVIRONMENT "FORENSICATOR_SCHEMA=${CMAKE_SOURCE_DIR}/../schema/forensicator.sql")

add_executable(test_pipeline test_pipeline.cpp)
target_link_libraries(test_pipeline PRIVATE forensicator_lib)
add_test(NAME test_pipeline COMMAND test_pipeline)

add_executable(test_json test_json.cpp)
target_link_libraries(test_json PRIVATE forensicator_lib)
add_test(NAME test_json COMMAND test_json)

add_executable(test_e2e test_e2e.cpp)
target_link_libraries(test_e2e PRIVATE forensicator_lib)
add_test(NAME test_e2e COMMAND test_e2e $<TARGET_FILE:forensicator>)
set_tests_properties(test_e2e PROPERTIES
    ENVIRONMENT "FORENSICATOR_SCHEMA=${CMAKE_SOURCE_DIR}/../schema/forensicator.sql")
