include(${CMAKE_CURRENT_LIST_DIR}/default.cmake)

add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
add_link_options(-fsanitize=address,undefined)
add_compile_definitions(ANVIL_ABI_SANITIZER_UNDEFINED=1)
