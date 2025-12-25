cmake_minimum_required(VERSION 3.14)
project(Log_Parser)
set(CMAKE_CXX_STANDARD 17)

set(GLFW_DIR "${CMAKE_SOURCE_DIR}/libs/glfw")
set(IMGUI_DIR "${CMAKE_SOURCE_DIR}/libs/imgui")
set(IMPLOT_DIR "${CMAKE_SOURCE_DIR}/libs/implot")
set(OTHERS_DIR "${CMAKE_SOURCE_DIR}/libs/others")

set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

set(IMPLOT_SOURCES
    ${IMPLOT_DIR}/implot.cpp
    ${IMPLOT_DIR}/implot_items.cpp
    ${IMPLOT_DIR}/implot_demo.cpp
)

set(OTHERS_SOURCES
    ${OTHERS_DIR}/IP2Location.c
)

include_directories(
    ${GLFW_DIR}/include
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${IMPLOT_DIR}
    ${OTHERS_DIR}
)

add_executable(${PROJECT_NAME}
    main.cpp
    ${IMGUI_SOURCES}
    ${IMPLOT_SOURCES}
    ${OTHERS_SOURCES}
)

if (WIN32)
    target_link_libraries(${PROJECT_NAME} "${GLFW_DIR}/lib-mingw-w64/libglfw3.a" opengl32 gdi32 user32 ws2_32)
elseif (UNIX)
    find_package(OpenGL REQUIRED)
    find_package(Threads REQUIRED)
    target_link_libraries(${PROJECT_NAME} glfw OpenGL::GL Threads::Threads dl X11)
endif()