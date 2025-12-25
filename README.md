# Suricata Log Analyzer

A multi-threaded C++ application designed to parse, analyze, and visualize Suricata logs (`eve.json`) in real-time, handle high-volume log data while rendering an interactive GUI.

## Features

* Real-time log parsing.
* Interactive dashboard.
* Data Visualization: Bar charts showing attacks per hour/minute, top source IPs, destination IPs, target countries, attack categories statistics, searchable table view.

## Tech

* Language: C++
* Build System: CMake
* GUI Framework: Dear ImGui + ImPlot
* Windowing/Input: GLFW + OpenGL3
* JSON Parsing: nlohmann/json
* Geolocation: IP2Location

### Build

### 1. Windows (MinGW)

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/PhucNB225377/Suricata-log-analyzer.git
    cd Suricata-log-analyzer
    ```

2.  **Create a build directory:**
    ```bash
    mkdir build
    cd build
    ```

3.  **Configure and build:**
    ```bash
    cmake -G "MinGW Makefiles" ..
    cmake --build .
    ```

4.  **Run:**
    ```bash
    cd ..
    ./build/Log_Parser.exe
    ```

### 2. Linux (Ubuntu / Debian / Kali)

1.  **Install Dependencies:**
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential cmake libglfw3-dev libgl1-mesa-dev
    ```

2.  **Clone the repository:**
    ```bash
    git clone https://github.com/PhucNB225377/Suricata-log-analyzer.git
    cd Suricata-log-analyzer
    ```

3.  **Create a build directory:**
    ```bash
    mkdir build
    cd build
    ```

4.  **Configure and build:**
    ```bash
    cmake ..
    make
    ```

5.  **Run:**
    ```bash
    cd ..
    ./build/Log_Parser
    ```

## Usage

1. Place Suricata log file at `sample/eve.json` or change `FILE_NAME` path in file `main.cpp`.
2. Locate the IP2Location database file at `database/IP2LOCATION-LITE-DB1.IPV6.BIN`.
3. Run the compiled executable.
4. Interact: view real-time graphs, switch to the table view to search logs, toggle between LIVE mode and historical data analysis in the Attack Trend tab.
