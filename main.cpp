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
    std::string category;
};

struct BarDetail {
    std::map<std::string, long long> src_count;
    std::map<std::string, long long> dest_count;
    std::map<std::string, long long> category_count;
    std::map<std::string, long long> country_count;
};

const std::string FILE_NAME = "sample/eve.json";
std::vector<LogInfo> all_logs;
std::map<std::string, long long> src_ip_total, dest_ip_total, country_total, category_total;
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
                {"category", j["alert"]["category"]},
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
        std::string category = j["category"];

        LogInfo info;
        info.timestamp = time;
        info.src_ip = src_ip;
        info.dest_ip = dest_ip;
        info.country = country;
        info.category = category;

        {
            std::lock_guard<std::mutex> lock(mtx);
            sum++;
            src_ip_total[src_ip]++;
            dest_ip_total[dest_ip]++;
            category_total[category]++;
            country_total[country]++;
            attacks_per_hour[time_hour]++;
            attacks_per_minute[time_minute]++;

            all_bar_hour[time_hour].src_count[src_ip]++;
            all_bar_hour[time_hour].dest_count[dest_ip]++;
            all_bar_hour[time_hour].category_count[category]++;
            all_bar_hour[time_hour].country_count[country]++;

            all_bar_minute[time_minute].src_count[src_ip]++;
            all_bar_minute[time_minute].dest_count[dest_ip]++;
            all_bar_minute[time_minute].category_count[category]++;
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
    // std::map<std::string, long long> categories;
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
        //     categories = category_total;
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

        // std::cout << "- Attacks by category:" << std::endl;
        // for (const auto &i : categories)
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

// CategoryTable
void ShowCategoryTable() {
    std::vector<sll> categories;
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (category_total.empty()) {
            ImGui::Text("No data available.");
            return;
        }
        categories.assign(category_total.begin(), category_total.end());
    }
    desc_sort(categories);

    ImGui::Text("Category Statistics");
    if (ImGui::BeginTable("CategoryTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, -1))) {
        ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthStretch); 
        ImGui::TableSetupColumn("Attacks", ImGuiTableColumnFlags_WidthFixed, 150.0f);
        ImGui::TableHeadersRow();

        for (const auto &i : categories) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%s", i.first.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%lld", i.second);
        }
        ImGui::EndTable();
    }
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

    if (ImGui::Button("Last 1 hour")) {
        is_filter = true;
        is_live = false;
        min_x = now - 3600;
        max_x = now;
    }

    ImGui::SameLine();

    if (ImGui::Button("Last 1 day")) {
        is_filter = true;
        is_live = false;
        min_x = now - 86400;
        max_x = now;
    }

    ImGui::SameLine();

    if (ImGui::Button("Last 3 days")) {
        is_filter = true;
        is_live = false;
        min_x = now - 259200;
        max_x = now;
    }

    static char from[30], to[30];
    static bool input_error = false;
    ImGui::Text("Advance:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##from", "2022-12-31T01:00", from, IM_ARRAYSIZE(from));
    ImGui::SameLine();
    ImGui::Text("-");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##to", "2025-12-31T01:00 or now", to, IM_ARRAYSIZE(to));
    ImGui::SameLine();

    if (ImGui::Button("Apply")) {
        std::string start(from), end(to);
        double t1 = parse_timestamp(start, true);
        double t2 = parse_timestamp(end, true);
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
        ImGui::TextColored(ImVec4(1, 0, 0, 1), "ERROR: Wrong input");
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

    // Draw graph
    ImGui::Text("Attack Trend");
    if (ImPlot::BeginPlot("AttackTrend", ImVec2(-1, -1))) {
        ImPlot::SetupAxes("Time", "Attacks");
        ImPlot::SetupAxisScale(ImAxis_X1, ImPlotScale_Time);

        if (is_live) ImPlot::SetupAxisLimits(ImAxis_X1, now - 1800, now, ImPlotCond_Always);
        else if (is_filter) {
            ImPlot::SetupAxisLimits(ImAxis_X1, min_x, max_x, ImPlotCond_Always);
            is_filter = false;
        }

        if (show_hour) ImPlot::SetupAxisLimits(ImAxis_Y1, 0, max_val_hour * 1.2, ImPlotCond_Always);
        else ImPlot::SetupAxisLimits(ImAxis_Y1, 0, max_val_minute * 1.2, ImPlotCond_Always);

        double current_range = ImPlot::GetPlotLimits().X.Max - ImPlot::GetPlotLimits().X.Min;
        show_hour = (current_range >= 86400);

        std::vector<double> &x = show_hour ? x_hour : x_minute;
        std::vector<double> &y = show_hour ? y_hour : y_minute;
        int max_idx = show_hour ? max_idx_hour : max_idx_minute;
        double width = show_hour ? 3600 : 60;

        if (!x.empty()) {
            ImPlot::PlotBars("##attacks", x.data(), y.data(), x.size(), width);

            ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(1.0f, 0.2f, 0.2f, 1.0f));
            ImPlot::PlotBars("##hightlight", &x[max_idx], &y[max_idx], 1, width);
            ImPlot::PopStyleColor();
        }

        // Hover
        if (ImPlot::IsPlotHovered()) {
            ImPlotPoint mouse = ImPlot::GetPlotMousePos();
            for (int i = 0; i < x.size(); i++) {
                if (mouse.x >= (x[i] - width/2) && mouse.x <= (x[i] + width/2)) {
                    ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(1.0f, 0.64f, 0.0f, 1.0f));
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
            if (ImPlot::IsPlotHovered() && ImGui::IsMouseClicked(0)) {
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

            if (ImGui::BeginTabItem("Categories")) {
                ImGui::Text("All type of attacks:");
                if (ImGui::BeginTable("CateTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY, ImVec2(0, -1))) {
                    ImGui::TableSetupColumn("Category", ImGuiTableColumnFlags_WidthStretch);
                    ImGui::TableSetupColumn("Numbers", ImGuiTableColumnFlags_WidthFixed, 100.0f);
                    ImGui::TableHeadersRow();

                    for (const auto &[category, count] : selected_bar.category_count) {
                        ImGui::TableNextRow();
                        ImGui::TableSetColumnIndex(0);
                        ImGui::Text("%s", category.c_str());
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
            std::string line_search = log->src_ip + " " + log->dest_ip + " " + log->country + " " + log->category;
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
        ImGui::TableSetupColumn("Category");
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
                ImGui::Text("%s", log->category.c_str());
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

            if (ImGui::BeginTabItem("Attack Category")) {
                ShowCategoryTable();
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