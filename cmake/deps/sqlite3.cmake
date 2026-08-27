find_package(SQLite3 3.40 REQUIRED)

if(NOT TARGET SQLite::SQLite3)
  message(FATAL_ERROR "SQLite did not provide SQLite::SQLite3")
endif()
