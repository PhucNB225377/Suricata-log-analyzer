#include <iostream>
#include <cstdio>
#include <thread>
#include <chrono>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>
#include "json.hpp"
#include "SharedQueue.hpp"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"
#include <GLFW/glfw3.h>
extern "C" {
    #include "IP2Location.h"
}

using sll = std::pair<std::string, long long>;

struct LogInfo {
    double timestamp;
    std::string src_ip;
    std::string dest_ip;
    std::string country;
    std::string signature;
};

struct BarDetail {
    std::map<std::string, long long> src_count;
    std::map<std::string, long long> dest_count;
    std::map<std::string, long long> signature_count;
    std::map<std::string, long long> country_count;
};

const std::string FILE_NAME = "sample/eve.json"; // Change correct path
std::vector<LogInfo> all_logs;
std::map<std::string, long long> src_ip_total, dest_ip_total, country_total, signature_total;
std::map<double, long long> attacks_per_hour, attacks_per_minute;
std::map<double, BarDetail> all_bar_hour, all_bar_minute;
long long sum = 0;
std::mutex mtx;

void desc_sort(std::vector<sll> &vec) {
    std::sort(vec.begin(), vec.end(), [](const sll &a, const sll &b) {
        return a.second > b.second;
    });
}

double parse_timestamp(std::string &timestamp, bool minute = false, bool second = false) {
    if (timestamp == "now") return (double)std::time(0);

    std::tm tm = {};
    std::time_t t;
    std::istringstream ss(timestamp);
    if (second) ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    else if (minute) ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M");
    else ss >> std::get_time(&tm, "%Y-%m-%dT%H");
    if (ss.fail()) return -1;
    #ifdef _WIN32
        t = (double)_mkgmtime(&tm);
    #else
        t = (double)timegm(&tm);
    #endif
    if (t == -1) return -1;
    return (double)t;
}

std::string format_time(double time, bool minute = false, bool second = false) {
    std::time_t t = (std::time_t)time;
    std::tm tm = {};
    #ifdef _WIN32
        gmtime_s(&tm, &t);
    #else
        gmtime_r(timer, buf);
    #endif
    std::ostringstream ss;
    if (second) ss << std::put_time(&tm, "%H:%M:%S %d/%m/%Y");
    else if (minute) ss << std::put_time(&tm, "%Hh%M %d/%m/%Y");
    else ss << std::put_time(&tm, "%Hh %d/%m/%Y");
    return ss.str();
}

void read_data(std::string filename, SharedQueue<nlohmann::json> &read_queue) {
    FILE* file = nullptr;
    char buffer[5000];

    file = fopen(filename.c_str(), "r");
    if (!file) {
        std::cerr << "ERROR: eve.json not found!" << std::endl;
        return;
    }

    while (1) {
        if (fgets(buffer, sizeof(buffer), file) != NULL) {
            std::string line(buffer);
            read_queue.push(nlohmann::json::parse(line));
        } 
        else {
            clearerr(file); 
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        }
    }
}

void parse_data(SharedQueue<nlohmann::json> &read_queue, SharedQueue<nlohmann::json> &parsed_queue, IP2Location *db) {
    while (1) {
        nlohmann::json j = read_queue.front();

        if (j.contains("event_type") && j["event_type"] == "alert") {
            std::string dest_ip = j.value("dest_ip", "0.0.0.0");
            std::string country_name = "Unknown";

            IP2LocationRecord *record = IP2Location_get_all(db, (char*)dest_ip.c_str());
            if (record != NULL) {
                country_name = record->country_long;
                if (country_name == "-") {
                    country_name = "Unknown/Local Network";
                }
                IP2Location_free_record(record);
            }

            parsed_queue.push({
                {"src_ip", j.value("src_ip", "0.0.0.0")},
                {"dest_ip", dest_ip},
                {"signature", j["alert"]["signature"]},
                {"timestamp", j["timestamp"]},
                {"country", country_name}
            });
        }
    }
}

void process_data(SharedQueue<nlohmann::json> &parsed_queue) {
    while (1) {
        nlohmann::json j = parsed_queue.front();

        std::string timestamp = j["timestamp"];
        double time = parse_timestamp(timestamp, true, true);
        double time_hour = parse_timestamp(timestamp);
        double time_minute = parse_timestamp(timestamp, true);
        std::string src_ip = j["src_ip"];
        std::string dest_ip = j["dest_ip"];
        std::string country = j["country"];
        std::string signature = j["signature"];

        LogInfo info;
        info.timestamp = time;
        info.src_ip = src_ip;
        info.dest_ip = dest_ip;
        info.country = country;
        info.signature = signature;

        {
            std::lock_guard<std::mutex> lock(mtx);
            sum++;
            src_ip_total[src_ip]++;
            dest_ip_total[dest_ip]++;
            signature_total[signature]++;
            country_total[country]++;
            attacks_per_hour[time_hour]++;
            attacks_per_minute[time_minute]++;

            all_bar_hour[time_hour].src_count[src_ip]++;
            all_bar_hour[time_hour].dest_count[dest_ip]++;
            all_bar_hour[time_hour].signature_count[signature]++;
            all_bar_hour[time_hour].country_count[country]++;

            all_bar_minute[time_minute].src_count[src_ip]++;
            all_bar_minute[time_minute].dest_count[dest_ip]++;
            all_bar_minute[time_minute].signature_count[signature]++;
            all_bar_minute[time_minute].country_count[country]++;

            all_logs.push_back(info);
            if (all_logs.size() > 8000) {
                all_logs.erase(all_logs.begin());
            }
        }
    }
}

void print_data() {
    // std::vector<sll> src_ips, dest_ips, countries;
    // std::map<std::string, long long> signatures;
    // std::map<double, long long> attacks;
    long long s = 0;
    while (1) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        // src_ips.clear();
        // dest_ips.clear();
        // countries.clear();
        {
            std::lock_guard<std::mutex> lock(mtx);
        //     if (src_ip_total.empty()) continue;

        //     src_ips.assign(src_ip_total.begin(), src_ip_total.end());
        //     dest_ips.assign(dest_ip_total.begin(), dest_ip_total.end());
        //     countries.assign(country_total.begin(), country_total.end());
        //     signatures = signature_total;
        //     attacks = attacks_per_hour;
            s = sum;
        }
        // desc_sort(src_ips);
        // desc_sort(dest_ips);
        // desc_sort(countries);

        // std::cout << "\n================*******================" << std::endl;
        // std::cout << "- Top source IP:" << std::endl;
        // for (int i = 0; i < 10 && i < src_ips.size(); i++)
        // std::cout << "     " << src_ips[i].first << ": " << src_ips[i].second << std::endl;
        // std::cout << std::endl;

        // std::cout << "- Top destination IP:" << std::endl;
        // for (int i = 0; i < 10 && i < dest_ips.size(); i++)
        // std::cout << "     " << dest_ips[i].first << ": " << dest_ips[i].second << std::endl;
        // std::cout << std::endl;

        // std::cout << "- Top country:" << std::endl;
        // for (int i = 0; i < 10 && i < countries.size(); i++)
        // std::cout << "     " << countries[i].first << ": " << countries[i].second << std::endl;
        // std::cout << std::endl;

        // std::cout << "- Attacks by signature:" << std::endl;
        // for (const auto &i : signatures)
        // std::cout << "     " << i.first << ": " << i.second << std::endl;
        // std::cout << std::endl;

        // std::cout << "- Number of attacks per hour:" << std::endl;
        // for (const auto &i : attacks) std::cout << "     " << i.first << ": " << i.second << std::endl;
        std::cout << s << std::endl;
        std::cout << "===========================================" << std::endl;
    }
}

// TopSrcIP
void ShowTopSrcIP() {
    std::vector<sll> src_ips;
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (src_ip_total.empty()) {
            ImGui::Text("No data available.");
            return;
        }
        src_ips.assign(src_ip_total.begin(), src_ip_total.end());
    }
    desc_sort(src_ips);

    int count = (src_ips.size() < 10) ? src_ips.size() : 10;
    double max_val = (double)src_ips[0].second;
    double x_attacks[10];
    double y_ip[10];
    const char* labels[10];

    for (int i = 0; i < count; i++) {
        int idx = count - 1 - i;
        y_ip[i] = (double)i;
        x_attacks[i] = (double)src_ips[idx].second;
        labels[i] = src_ips[idx].first.c_str();
    }

    ImGui::Text("Top Source IP");
    if (ImPlot::BeginPlot("TopSrcIP", ImVec2(-1, -1))) {
        ImPlot::SetupAxes("Attacks", "IP Addr");
        ImPlot::SetupAxisLimits(ImAxis_Y1, -0.5, count - 0.5, ImPlotCond_Always);
        ImPlot::SetupAxisTicks(ImAxis_Y1, y_ip, count, labels);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, max_val * 1.2, ImPlotCond_Always);
        ImPlot::PlotBars("##attacks", x_attacks, y_ip, count, 0.6f, ImPlotBarsFlags_Horizontal);
        for (int i = 0; i < count; i++) {
            ImPlot::PlotText(std::to_string((long long)x_attacks[i]).c_str(), x_attacks[i], y_ip[i], ImVec2(15, 0));
        }
        ImPlot::EndPlot();
    }
}

// TopDestIP
void ShowTopDestIP() {
    std::vector<sll> dest_ips;
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (dest_ip_total.empty()) {
            ImGui::Text("No data available.");
            return;
        }
        dest_ips.assign(dest_ip_total.begin(), dest_ip_total.end());
    }
    desc_sort(dest_ips);

    int count = (dest_ips.size() < 10) ? dest_ips.size() : 10;
    double max_val = (double)dest_ips[0].second;
    double x_attacks[10];
    double y_ip[10];
    const char* labels[10];

    for (int i = 0; i < count; i++) {
        int idx = count - 1 - i;
        y_ip[i] = (double)i;
        x_attacks[i] = (double)dest_ips[idx].second;
        labels[i] = dest_ips[idx].first.c_str(); 
    }

    ImGui::Text("Top Destination IP");
    if (ImPlot::BeginPlot("TopDestIP", ImVec2(-1, -1))) {
        ImPlot::SetupAxes("Attacks", "IP Addr");
        ImPlot::SetupAxisLimits(ImAxis_Y1, -0.5, count - 0.5, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, max_val * 1.2, ImPlotCond_Always);
        ImPlot::SetupAxisTicks(ImAxis_Y1, y_ip, count, labels);
        ImPlot::PlotBars("##attacks", x_attacks, y_ip, count, 0.6f, ImPlotBarsFlags_Horizontal);
        for (int i = 0; i < count; i++) {
            ImPlot::PlotText(std::to_string((long long)x_attacks[i]).c_str(), x_attacks[i], y_ip[i], ImVec2(15, 0));
        }
        ImPlot::EndPlot();
    }
}

// TopCountry
void ShowTopCountry() {
    std::vector<sll> countries;
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (country_total.empty()) {
            ImGui::Text("No data available.");
            return;
        }
        countries.assign(country_total.begin(), country_total.end());
    }
    desc_sort(countries);

    int count = (countries.size() < 10) ? countries.size() : 10;
    double max_val = (double)countries[0].second;
    double x_attacks[10];
    double y_country[10];
    const char* labels[10];

    for (int i = 0; i < count; i++) {
        int idx = count - 1 - i;
        y_country[i] = (double)i;
        x_attacks[i] = (double)countries[idx].second;
        labels[i] = countries[idx].first.c_str(); 
    }

    ImGui::Text("Top Country");
    if (ImPlot::BeginPlot("TopCountry", ImVec2(-1, -1))) {
        ImPlot::SetupAxes("Attacks", "Country");
        ImPlot::SetupAxisLimits(ImAxis_Y1, -0.5, count - 0.5, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, max_val * 1.2, ImPlotCond_Always);
        ImPlot::SetupAxisTicks(ImAxis_Y1, y_country, count, labels);
        ImPlot::PlotBars("##attacks", x_attacks, y_country, count, 0.6f, ImPlotBarsFlags_Horizontal);
        for (int i = 0; i < count; i++) {
            ImPlot::PlotText(std::to_string((long long)x_attacks[i]).c_str(), x_attacks[i], y_country[i], ImVec2(15, 0));
        }
        ImPlot::EndPlot();
    }
}

// SignatureTable
void ShowSignatureTable() {
    std::vector<sll> signatures;
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (signature_total.empty()) {
            ImGui::Text("No data available.");
            return;
        }
        signatures.assign(signature_total.begin(), signature_total.end());
    }
    desc_sort(signatures);

    ImGui::Text("Signature Statistics");
    if (ImGui::BeginTable("SignatureTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, -1))) {
        ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_WidthStretch); 
        ImGui::TableSetupColumn("Attacks", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableHeadersRow();

        for (const auto &i : signatures) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%s", i.first.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%lld", i.second);
        }
        ImGui::EndTable();
    }
}

struct TimeState {
    int year_idx = 10;
    int month_idx = 0;
    int day_idx = 0;
    int hour_idx = 0;
    int minute_idx = 0;
};

const char* years[] = {
    "2015","2016", "2017", "2018", "2019", "2020",
    "2021", "2022", "2023", "2024", "2025", "2026",
    "2027", "2028", "2029", "2030", "2031", "2032",
    "2033", "2034", "2035", "2036", "2037", "2038",
    "2039", "2040", "2041", "2042", "2043", "2044",
    "2045", "2046", "2047", "2048", "2049", "2050"
};
const char* months[] = {
    "01", "02", "03", "04", "05", "06",
    "07", "08", "09", "10", "11", "12"
};
const char* days[] = {
    "01", "02", "03", "04", "05", "06", "07", "08", "09", "10",
    "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
    "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31"
};
const char* hours[] = {
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11",
    "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23"
};
const char* minutes[] = {
    "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11",
    "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23",
    "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35",
    "36", "37", "38", "39", "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59"
};

// TimePicker
std::string TimePicker(const char* label, TimeState &state) {
    ImGui::PushID(label);

    ImGuiComboFlags flags = ImGuiComboFlags_NoArrowButton | ImGuiComboFlags_WidthFitPreview;

    const char* hour = hours[state.hour_idx];
    if (ImGui::BeginCombo("##hour", hour, flags)) {
        for (int i = 0; i < 24; i++) {
            if (ImGui::Selectable(hours[i], state.hour_idx == i)) {
                state.hour_idx = i;
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::Text(":");
    ImGui::SameLine();

    const char* minute = minutes[state.minute_idx];
    if (ImGui::BeginCombo("##minute", minute, flags)) {
        for (int i = 0; i < 60; i++) {
            if (ImGui::Selectable(minutes[i], state.minute_idx == i)) {
                state.minute_idx = i;
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::Text(" ");
    ImGui::SameLine();

    const char* day = days[state.day_idx];
    if (ImGui::BeginCombo("##day", day, flags)) {
        for (int i = 0; i < 31; i++) {
            if (ImGui::Selectable(days[i], state.day_idx == i)) {
                state.day_idx = i;
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::Text("/");
    ImGui::SameLine();

    const char* month = months[state.month_idx];
    if (ImGui::BeginCombo("##month", month, flags)) {
        for (int i = 0; i < 12; i++) {
            if (ImGui::Selectable(months[i], state.month_idx == i)) {
                state.month_idx = i;
            }
        }
        ImGui::EndCombo();
    }

    ImGui::SameLine();
    ImGui::Text("/");
    ImGui::SameLine();

    const char* year = years[state.year_idx];
    if (ImGui::BeginCombo("##year", year, flags)) {
        for (int i = 0; i < 36; i++) {
            if (ImGui::Selectable(years[i], state.year_idx == i)) {
                state.year_idx = i;
            }
        }
        ImGui::EndCombo();
    }

    ImGui::PopID();

    std::ostringstream ss;
    ss << year << "-" << month << "-" << day << "T" << hour << ":" << minute;
    return ss.str();
}

// AttackTrend
void ShowAttackTrend() {
    std::vector<std::pair<double, long long>> per_hour, per_minute;
    {
        std::lock_guard<std::mutex> lock(mtx);
        per_hour.assign(attacks_per_hour.begin(), attacks_per_hour.end());
        per_minute.assign(attacks_per_minute.begin(), attacks_per_minute.end());
    }

    // Time filter
    static bool is_filter = false, is_live = true;
    static double min_x, max_x;
    double now = (double)std::time(0);

    ImGui::Text("Time filter:");
    ImGui::SameLine();

    if (is_live) {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.0f, 0.0f, 1.0f));
        if (ImGui::Button("LIVE")) is_live = false;
        ImGui::PopStyleColor();
    }
    else {
        if (ImGui::Button("LIVE")) is_live = true;
    }

    ImGui::SameLine();
    ImGui::Text("|");
    ImGui::SameLine();
    ImGui::Text(" ");
    ImGui::SameLine();

    if (ImGui::Button("Hours")) {
        ImGui::OpenPopup("menu_hours");
    }
    if (ImGui::BeginPopup("menu_hours")) {
        for (int i = 1; i <= 3; i++) {
            if (ImGui::Selectable(("Last " + std::to_string(i) + " hour" + (i > 1 ? "s" : "")).c_str())) {
                is_filter = true;
                is_live = false;
                min_x = now - i * 3600;
                max_x = now;
            }
        }
        ImGui::EndPopup();
    }

    ImGui::SameLine();
    ImGui::Text(" ");
    ImGui::SameLine();

    if (ImGui::Button("Days")) {
        ImGui::OpenPopup("menu_days");
    }
    if (ImGui::BeginPopup("menu_days")) {
        for (int i = 1; i <= 3; i++) {
            if (ImGui::Selectable(("Last " + std::to_string(i) + " day" + (i > 1 ? "s" : "")).c_str())) {
                is_filter = true;
                is_live = false;
                min_x = now - i * 86400;
                max_x = now;
            }
        }
        ImGui::EndPopup();
    }

    ImGui::SameLine();
    ImGui::Text(" ");
    ImGui::SameLine();

    if (ImGui::Button("Weeks")) {
        ImGui::OpenPopup("menu_weeks");
    }
    if (ImGui::BeginPopup("menu_weeks")) {
        for (int i = 1; i <= 3; i++) {
            if (ImGui::Selectable(("Last " + std::to_string(i) + " week" + (i > 1 ? "s" : "")).c_str())) {
                is_filter = true;
                is_live = false;
                min_x = now - i * 604800;
                max_x = now;
            }
        }
        ImGui::EndPopup();
    }

    ImGui::SameLine();
    ImGui::Text(" ");
    ImGui::SameLine();

    if (ImGui::Button("Months")) {
        ImGui::OpenPopup("menu_months");
    }
    if (ImGui::BeginPopup("menu_months")) {
        for (int i = 1; i <= 3; i++) {
            if (ImGui::Selectable(("Last " + std::to_string(i) + " month" + (i > 1 ? "s" : "")).c_str())) {
                is_filter = true;
                is_live = false;
                min_x = now - i * 2592000;
                max_x = now;
            }
        }
        ImGui::EndPopup();
    }

    ImGui::SameLine();
    ImGui::Text(" ");
    ImGui::SameLine();

    if (ImGui::Button("Years")) {
        ImGui::OpenPopup("menu_years");
    }
    if (ImGui::BeginPopup("menu_years")) {
        for (int i = 1; i <= 3; i++) {
            if (ImGui::Selectable(("Last " + std::to_string(i) + " year" + (i > 1 ? "s" : "")).c_str())) {
                is_filter = true;
                is_live = false;
                min_x = now - i * 31536000;
                max_x = now;
            }
        }
        ImGui::EndPopup();
    }

    // Advance filter
    std::string from, to;
    static bool input_error = false;
    static TimeState from_state, to_state;
    ImGui::Text("Advance:");
    ImGui::SameLine();
    ImGui::Text(" ");
    ImGui::SameLine();
    from = TimePicker("from", from_state);
    ImGui::SameLine();
    ImGui::Text(" => ");
    ImGui::SameLine();
    to = TimePicker("to", to_state);
    ImGui::SameLine();

    if (ImGui::Button("Apply")) {
        double t1 = parse_timestamp(from, true);
        double t2 = parse_timestamp(to, true);
        if (t1 == -1 || t2 == -1 || t1 > t2) {
            input_error = true;
        }
        else {
            is_filter = true;
            is_live = false;
            input_error = false;
            min_x = t1;
            max_x = t2;
        }
    }

    if (input_error) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "ERROR: Wrong time input");
    }

    std::vector<double> x_hour, y_hour;
    std::vector<double> x_minute, y_minute;
    double max_val_hour = 0; int max_idx_hour = -1;
    double max_val_minute = 0; int max_idx_minute = -1;
    static bool show_hour = true;

    int i = 0;
    for (const auto &a : per_hour) {
        x_hour.push_back(a.first);
        y_hour.push_back((double)a.second);
        if (a.second > max_val_hour) {
            max_val_hour = a.second;
            max_idx_hour = i;
        }
        i++;
    }

    i = 0;
    for (const auto &a : per_minute) {
        x_minute.push_back(a.first);
        y_minute.push_back((double)a.second);
        if (a.second > max_val_minute) {
            max_val_minute = a.second;
            max_idx_minute = i;
        }
        i++;
    }

    // Variable for bar detail
    static BarDetail selected_bar;
    static double selected_time;
    static long long selected_attacks;
    static bool open_popup = false;

    // Threshold for colormap & slider
    static int color_threshold = 100;
    ImGui::Text("Color threshold:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(500);
    ImGui::SliderInt("##threshold", &color_threshold, 10, 5000);
    ImGui::SameLine();

    // Draw graph
    ImGui::Text("Attack Trend");
    ImPlot::GetStyle().Use24HourClock = true;
    if (ImPlot::BeginPlot("AttackTrend", ImVec2(ImGui::GetContentRegionAvail().x - 68, -1))) {
        ImPlot::SetupAxes("Time", "Attacks");
        ImPlot::SetupAxisScale(ImAxis_X1, ImPlotScale_Time);

        if (is_live) ImPlot::SetupAxisLimits(ImAxis_X1, now - 1800, now, ImPlotCond_Always);
        else if (is_filter) {
            ImPlot::SetupAxisLimits(ImAxis_X1, min_x, max_x, ImPlotCond_Always);
            is_filter = false;
        }

        if (show_hour) ImPlot::SetupAxisLimits(ImAxis_Y1, 0, max_val_hour * 1.2, ImPlotCond_Always);
        else ImPlot::SetupAxisLimits(ImAxis_Y1, 0, max_val_minute * 1.2, ImPlotCond_Always);

        show_hour = (ImPlot::GetPlotLimits().X.Size() >= 86400);

        std::vector<double> &x = show_hour ? x_hour : x_minute;
        std::vector<double> &y = show_hour ? y_hour : y_minute;
        int max_idx = show_hour ? max_idx_hour : max_idx_minute;
        double width = show_hour ? 3600 : 60;

        if (!x.empty()) {
            ImPlot::PushColormap(ImPlotColormap_Jet);
            for (int i = 0; i < x.size(); i++) {
                float t = y[i] / color_threshold;
                if (t > 1.0) t = 1.0;
                ImPlot::PushStyleColor(ImPlotCol_Fill, ImPlot::SampleColormap(t));
                ImPlot::PlotBars("##attacks", &x[i], &y[i], 1, width);
                ImPlot::PopStyleColor();
            }
            ImGui::SameLine();
            ImPlot::ColormapScale("##scale", 0, (double)color_threshold, ImVec2(60, -1));
            ImPlot::PopColormap();
        }

        // Hover
        if (ImPlot::IsPlotHovered()) {
            ImPlotPoint mouse = ImPlot::GetPlotMousePos();
            for (int i = 0; i < x.size(); i++) {
                if (mouse.x >= (x[i] - width/2) && mouse.x <= (x[i] + width/2)) {
                    ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(0.2f, 0.2f, 0.2f, 1.0f));
                    ImPlot::PlotBars("##hover", &x[i], &y[i], 1, width);
                    ImPlot::PopStyleColor();

                    ImGui::BeginTooltip();
                    if (show_hour) ImGui::Text("Time: %s", format_time(x[i]).c_str());
                    else ImGui::Text("Time: %s", format_time(x[i], true).c_str());
                    ImGui::Text("Attacks: %lld", (long long)y[i]);
                    ImGui::EndTooltip();
                    break;
                }
            }

            // Click
            if (ImGui::IsMouseClicked(0)) {
                ImPlotPoint mouse = ImPlot::GetPlotMousePos();
                if (!x.empty()){
                    for (int i = 0; i < x.size(); i++) {
                        if (mouse.x >= (x[i] - width/2) && mouse.x <= (x[i] + width/2)) {
                            {
                                std::lock_guard<std::mutex> lock(mtx);
                                selected_bar = show_hour ? all_bar_hour[x[i]] : all_bar_minute[x[i]];
                            }
                            selected_time = x[i];
                            selected_attacks = (long long)y[i];
                            open_popup = true;
                            break;
                        }
                    }
                }
            }
        }
        ImPlot::EndPlot();
    }

    if (open_popup) {
        ImGui::OpenPopup("Detail");
        open_popup = false;
    }

    ImGui::SetNextWindowSize(ImVec2(600, 450), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("Detail", NULL, ImGuiWindowFlags_NoResize)) {
        std::map<double, BarDetail> all_bar = show_hour ? all_bar_hour : all_bar_minute;
        ImGui::Text("Time: %s", format_time(selected_time, !show_hour).c_str());
        ImGui::SameLine();
        ImGui::Text("|");
        ImGui::SameLine();
        ImGui::Text("Total attacks: %lld", selected_attacks);
        ImGui::Separator();

        if (ImGui::BeginTabBar("Tabs")) {
            if (ImGui::BeginTabItem("Attackers")) {
                ImGui::Text("All attackers:");
                if (ImGui::BeginTable("SrcTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, -1))) {
                    ImGui::TableSetupColumn("IP", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Numbers", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableHeadersRow();

                    for (const auto &[ip, count] : selected_bar.src_count) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%s", ip.c_str());
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%lld", count);
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Victims")) {
                ImGui::Text("All victims:");
                if (ImGui::BeginTable("DestTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, -1))) {
                    ImGui::TableSetupColumn("IP", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Numbers", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableHeadersRow();

                    for (const auto &[ip, count] : selected_bar.dest_count) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%s", ip.c_str());
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%lld", count);
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Signatures")) {
                ImGui::Text("All type of attacks:");
                if (ImGui::BeginTable("CateTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, -1))) {
                    ImGui::TableSetupColumn("Signature", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Numbers", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableHeadersRow();

                    for (const auto &[signature, count] : selected_bar.signature_count) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%s", signature.c_str());
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%lld", count);
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Countries")) {
                ImGui::Text("All attacked countries:");
                if (ImGui::BeginTable("CounTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, -1))) {
                    ImGui::TableSetupColumn("Country", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Numbers", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableHeadersRow();

                    for (const auto &[country, count] : selected_bar.country_count) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%s", country.c_str());
                        ImGui::TableSetColumnIndex(1);
                        ImGui::Text("%lld", count);
                    }
                    ImGui::EndTable();
                }
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        if (ImGui::Button("Close", ImVec2(150, 0))) ImGui::CloseCurrentPopup();
        
        ImGui::EndPopup();
    }
}

// LogTable
void ShowLogTable() {
    static std::vector<LogInfo> display_logs;
    static double last_update_time = 0.0;
    double current_time = ImGui::GetTime();
    if (current_time - last_update_time > 5.0 || display_logs.empty()) {
        std::lock_guard<std::mutex> lock(mtx);
        display_logs = all_logs;
        last_update_time = current_time;
    }

    // Filter
    static ImGuiTextFilter filter;
    std::vector<LogInfo*> filtered_data;
    if (filter.IsActive()) {
        for (auto log = display_logs.rbegin(); log != display_logs.rend(); log++) {
            std::string line_search = log->src_ip + " " + log->dest_ip + " " + log->country + " " + log->signature;
            if (filter.PassFilter(line_search.c_str())) {
                filtered_data.push_back(&(*log));
            }
        }
    }
    else {
        for (auto log = display_logs.rbegin(); log != display_logs.rend(); log++) {
            filtered_data.push_back(&(*log));
        }
    }

    // Draw table
    ImGui::Text("Update Log Table after: %.1f seconds", 5.0 - (current_time - last_update_time));
    filter.Draw("Filter");
    ImGui::TextColored(ImVec4(1, 1, 0, 1), "Matched: %d / %d", (int)filtered_data.size(), (int)display_logs.size());
    if (ImGui::BeginTable("LogTable", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImGui::GetContentRegionAvail())) {
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Source IP Addr");
        ImGui::TableSetupColumn("Destination IP Addr");
        ImGui::TableSetupColumn("Country");
        ImGui::TableSetupColumn("Signature");
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(filtered_data.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                LogInfo* log = filtered_data[i];

                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%s", format_time(log->timestamp, true, true).c_str());

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%s", log->src_ip.c_str());

                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s", log->dest_ip.c_str());

                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s", log->country.c_str());

                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%s", log->signature.c_str());
            }
        }
        ImGui::EndTable();
    }
}

int main() {
    IP2Location *IP_country_DB = IP2Location_open((char*)"database/IP2LOCATION-LITE-DB1.IPV6.BIN");
    if (IP_country_DB == NULL) {
        std::cerr << "ERROR: IP2LOCATION-LITE-DB1.IPV6.BIN not found!" << std::endl;
        return -1;
    }

    SharedQueue<nlohmann::json> read_queue, parsed_queue;

    std::thread read_thread(read_data, FILE_NAME, std::ref(read_queue));
    std::thread parse_thread(parse_data, std::ref(read_queue), std::ref(parsed_queue), IP_country_DB);
    std::thread process_thread(process_data, std::ref(parsed_queue));
    std::thread print_thread(print_data);

    read_thread.detach();
    parse_thread.detach();
    process_thread.detach();
    print_thread.detach();

    // GUI
    // Initialize GLFW
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return -1;
    }

    // GL 3.0 + GLSL 130 (Windows and Linux)
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Create window
    GLFWwindow* window = glfwCreateWindow(1400, 900, "Log Parser", nullptr, nullptr);
    if (!window) {
        std::cerr << "Failed to create GLFW window" << std::endl;
        glfwTerminate();
        return -1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(0); // Disable vsync

    // Setup context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGuiIO &io = ImGui::GetIO(); (void)io;

    // Setup style
    ImGui::StyleColorsDark();

    // Setup backend
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // Main loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        // Start frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Draw windows
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);

        ImGui::Begin("Dashboard", NULL, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove);

        ImGui::BeginChild("GraphRegion", ImVec2(0, 500), true);
        
        // Graph tabs
        if (ImGui::BeginTabBar("GraphTabs")) {
            if (ImGui::BeginTabItem("Attack Trend")) {
                ShowAttackTrend();
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Top Src IP")) {
                ShowTopSrcIP();
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Top Dest IP")) {
                ShowTopDestIP();
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Top Country")) {
                ShowTopCountry();
                ImGui::EndTabItem();
            }

            if (ImGui::BeginTabItem("Attack signature")) {
                ShowSignatureTable();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::EndChild();

        ImGui::Separator();

        // Log table
        ShowLogTable();

        ImGui::End();

        // Render
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        // Swap buffers
        glfwSwapBuffers(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImPlot::DestroyContext();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    IP2Location_close(IP_country_DB);

    return 0;
}