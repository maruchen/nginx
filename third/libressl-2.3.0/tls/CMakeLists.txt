include_directories(
	.
	../include
	../include/compat
)

set(
	TLS_SRC
	tls.c
	tls_client.c
	tls_config.c
	tls_conninfo.c
	tls_server.c
	tls_peer.c
	tls_util.c
	tls_verify.c
)


if(NOT HAVE_STRCASECMP)
	set(TLS_SRC ${TLS_SRC} strsep.c)
endif()

if (BUILD_SHARED)
	add_library(tls-objects OBJECT ${TLS_SRC})
	add_library(tls STATIC $<TARGET_OBJECTS:tls-objects>)
	add_library(tls-shared SHARED $<TARGET_OBJECTS:tls-objects>)
	set_target_properties(tls-shared PROPERTIES OUTPUT_NAME tls)
	set_target_properties(tls-shared PROPERTIES VERSION ${TLS_VERSION}
		SOVERSION ${TLS_MAJOR_VERSION})
	install(TARGETS tls tls-shared DESTINATION lib)
else()
	add_library(tls STATIC ${TLS_SRC})
	install(TARGETS tls DESTINATION lib)
endif()

