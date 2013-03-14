cmake_minimum_required(VERSION 2.8)
project(eyefiserver)

set(CMAKE_MODULE_PATH
	${CMAKE_MODULE_PATH}
	"${CMAKE_SOURCE_DIR}/"
)

find_package(LibXml2)
find_package(LibMicroHTTPD)

add_subdirectory(geolocate)

include_directories(${LIBXML2_INCLUDE_DIR} ${MHD_INCLUDE_DIR})

add_executable(eyefiserver main.c hexString.c)
target_link_libraries(eyefiserver ${CURL_LIBRARY} ${LIBXML2_LIBRARIES} ${MHD_LIBRARIES})
