include(${CMAKE_CURRENT_LIST_DIR}/default.cmake)

add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
add_link_options(-fsanitize=undefined)
