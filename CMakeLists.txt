cmake_minimum_required(VERSION 2.6)

PROJECT(ucentral C)

ADD_DEFINITIONS(-Wall -Werror)
IF(CMAKE_C_COMPILER_VERSION VERSION_GREATER 6)
	ADD_DEFINITIONS(-Wextra -Werror=implicit-function-declaration)
	ADD_DEFINITIONS(-Wformat -Werror=format-security -Werror=format-nonliteral)
ENDIF()
ADD_DEFINITIONS(-Os -std=gnu99 -g3 -Wmissing-declarations -Wno-unused-parameter)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

SET(SOURCES main.c config.c proto.c ubus.c task.c cmd.c blink.c apply.c upload.c rebootlog.c event.c collide.c)

FIND_LIBRARY(ubus NAMES ubus)
FIND_LIBRARY(blobmsg_json NAMES blobmsg_json)
FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(websockets NAMES websockets)
FIND_PATH(ubus_include_dir NAMES libubus.h)
FIND_PATH(libwebsockets_include_dir NAMES libwebsockets.h)
INCLUDE_DIRECTORIES(${ubox_include_dir} ${ubus_include_dir} ${libwebsockets_include_dir})

ADD_EXECUTABLE(ucentral ${SOURCES})

TARGET_LINK_LIBRARIES(ucentral ${ubox} ${ubus} ${websockets} ${blobmsg_json} z)

INSTALL(TARGETS ucentral
	RUNTIME DESTINATION sbin
)
