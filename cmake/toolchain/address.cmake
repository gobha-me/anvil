include(${CMAKE_CURRENT_LIST_DIR}/default.cmake)

add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
add_link_options(-fsanitize=address)
