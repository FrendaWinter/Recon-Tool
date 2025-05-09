#include "./CLI11.hpp"
#include <iostream>
#include <cstdlib>
#include <string>

int main(int argc, char** argv) {
    CLI::App app{"frecon - Fast Recon Tool for Bug Bounty"};

    // Parameters for subdomain subcommand
    std::string tool;
    std::string output;
    std::string domain;
    bool check_alive = false;

    // Subcommand: subdomain
    auto subdomain_cmd = app.add_subcommand("subdomain", "Perform subdomain enumeration");

    subdomain_cmd->add_option("--tool", tool, "Tool to use for subdomain enumeration (e.g., gobuster)")
                 ->required();
    subdomain_cmd->add_option("-o,--output", output, "Output file to save results");
    subdomain_cmd->add_option("-d,--domain", domain, "Target domain")
                 ->required();
    subdomain_cmd->add_flag("--alive", check_alive, "Check alive subdomains using httpx");

    CLI11_PARSE(app, argc, argv);

    // Execute subdomain command
    if (*subdomain_cmd) {
        std::cout << "[*] Starting subdomain enumeration for domain: " << domain << "\n";

        if (tool == "gobuster") {
            std::string gobuster_cmd = "gobuster dns -d " + domain;

            if (!output.empty()) {
                gobuster_cmd += " -o " + output;
            }

            gobuster_cmd += " -w /usr/share/wordlists/dns/common.txt";  // Modify this path as needed
            std::cout << "[*] Running: " << gobuster_cmd << "\n";
            int result = std::system(gobuster_cmd.c_str());
            if (result != 0) {
                std::cerr << "[!] Gobuster command failed with code: " << result << "\n";
            }
        } else {
            std::cerr << "[!] Unsupported tool: " << tool << "\n";
            return 1;
        }

        if (check_alive && !output.empty()) {
            std::string httpx_cmd = "httpx -l " + output + " -o alive_" + output;
            std::cout << "[*] Checking alive subdomains with httpx...\n";
            std::cout << "[*] Running: " << httpx_cmd << "\n";
            int result = std::system(httpx_cmd.c_str());
            if (result != 0) {
                std::cerr << "[!] Httpx command failed with code: " << result << "\n";
            }
        }
    }

    return 0;
}
