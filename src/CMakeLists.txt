cmake_minimum_required(VERSION 3.24)
project(FasterStartup VERSION 1.0.0 LANGUAGES CXX)
if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Faster Startup requires 64-bit Windows")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(FasterStartup SHARED
  Plugin.cpp
  DirectoryCache.cpp
  EngineInfoHook.cpp
  ImportHooks.cpp
  Persistence.cpp
  ProgressPanel.cpp
  VirtualView.cpp)
target_compile_definitions(FasterStartup PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
target_link_libraries(FasterStartup PRIVATE bcrypt user32 gdi32 shell32 ole32)
if(MSVC)
  target_compile_options(FasterStartup PRIVATE /W4 /WX /permissive- /EHsc /utf-8 /Zi)
  target_link_options(FasterStartup PRIVATE /DEBUG:FULL /OPT:REF /OPT:ICF /INCREMENTAL:NO)
endif()

install(TARGETS FasterStartup RUNTIME DESTINATION F4SE/Plugins)
