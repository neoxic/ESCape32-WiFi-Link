idf_component_register(SRCS main.c PRIV_REQUIRES espressif__mdns)
set(lang_map en:EN de:DE ru:РУ zh:中)
string(REGEX REPLACE "([a-z][a-z]):([^;]+)" "XX(\\1)" LANG_LIST "${lang_map}")
string(REGEX REPLACE "([a-z][a-z]):([^;]+)" "<option value=\"\\1\">\\2</option>" LANG_OPTS "${lang_map}")
list(JOIN LANG_LIST " " LANG_LIST)
list(JOIN LANG_OPTS "" LANG_OPTS)
configure_file(build_defs.h.in build_defs.h @ONLY)
target_include_directories(${COMPONENT_TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
file(GLOB files root*.*)
foreach(file ${files})
	get_filename_component(name ${file} NAME)
	configure_file(${name} ${name} @ONLY)
	add_custom_command(
		OUTPUT ${name}.gz
		COMMAND gzip -f ${name}
		DEPENDS ${name}
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	)
	target_add_binary_data(${COMPONENT_TARGET} ${CMAKE_CURRENT_BINARY_DIR}/${name}.gz BINARY DEPENDS ${name}.gz)
endforeach()
