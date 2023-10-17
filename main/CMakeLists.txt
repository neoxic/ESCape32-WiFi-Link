idf_component_register(SRCS main.c PRIV_REQUIRES espressif__mdns)
configure_file(root.html root.html @ONLY)
add_custom_command(
	OUTPUT root.html.gz
	COMMAND gzip -f root.html
	DEPENDS root.html
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
add_custom_target(${COMPONENT_TARGET}-embedded DEPENDS root.html.gz)
add_dependencies(${COMPONENT_TARGET} ${COMPONENT_TARGET}-embedded)
target_add_binary_data(${COMPONENT_TARGET} ${CMAKE_CURRENT_BINARY_DIR}/root.html.gz BINARY)
