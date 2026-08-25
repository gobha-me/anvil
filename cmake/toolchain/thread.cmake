include(${CMAKE_CURRENT_LIST_DIR}/default.cmake)

add_compile_options(-fsanitize=thread)
add_link_options(-fsanitize=thread)
