
set(SANITIZE_ADDRESS TRUE)

#
# search for sanitizers
#
find_package(Sanitizers)

find_package(CxxTest)
if(CXXTEST_FOUND)
	enable_testing()
	set(EXECUTABLE_OUTPUT_PATH ${EXECUTABLE_OUTPUT_PATH}/cxxtests)
	
	#include_directories(${GPHOTO2PP_SOURCE_DIR}/gphoto2pp/include)
	include_directories(${CXXTEST_INCLUDE_DIR})
	
	# First copies the testing png to the ../build/tests folder where all the test runners (*.cc) files are generated. 
    # That's where ctest executes it's tests from
	# file(COPY unit_test_sample_input.jpg DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
	FILE(GLOB TESTS_SOURCE_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.h")
	foreach(testssourcefile ${TESTS_SOURCE_FILES})
		# I used a simple string replace, to cut off .h.
		string(REPLACE ".h" "" TESTNAME ${testssourcefile})
		CXXTEST_ADD_TEST(${TESTNAME} "${testname}.cc" "${CMAKE_CURRENT_SOURCE_DIR}/${testssourcefile}")
		# Make sure YourLib is linked to each app
		target_link_libraries(${TESTNAME} libftp++ ${LIBS})
        if (Sanitizers_FOUND)
            message(STATUS "Sanitizers found")
            add_sanitizers(${TESTNAME})
        endif (Sanitizers_FOUND)
	endforeach(testssourcefile ${TESTS_SOURCE_FILES})
else (CXXTEST_FOUND)
    message("CXXTEST_FOUND: ${CXXTEST_FOUND}")
endif(CXXTEST_FOUND)
