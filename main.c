#define NOB_IMPLEMENTATION
#include "nob.h"

#define OUTPUT_FOLDER "output/"

Nob_String_Array output_file_list = {
    .capacity = 0,
    .count = 0,
    .items = NULL
};

void print_command(Nob_Cmd cmd) {
    Nob_String_Builder sb = {0};
    nob_cmd_render(cmd, &sb);
    nob_sb_append_null(&sb);
    nob_log(NOB_INFO, "CMD: %s", sb.items);
    nob_sb_free(sb);
    memset(&sb, 0, sizeof(sb));
}

bool subfinder_subdomain_scan(const char* domain) {
    Nob_Cmd cmd = {0};
    Nob_String_Builder sb = {0};
    nob_sb_append_cstr(&sb, OUTPUT_FOLDER);
    
    if (!nob_mkdir_if_not_exists(OUTPUT_FOLDER"subfinder")) return 1;
    nob_sb_append_cstr(&sb, "subfinder/");
    nob_sb_append_cstr(&sb, domain); 
    nob_sb_append_cstr(&sb, ".txt");

    // subfinder -d example.com -all -recursive > subexample.com.txt
    printf("Domain %s\n", domain);
    nob_cmd_append(&cmd, "subfinder", "-all", "-recursive", "-d", domain, "-o", sb.items);

    if (!nob_cmd_run_sync_and_reset(&cmd)) return false;
    print_command(cmd);
    return true;
}

bool amass_subdomain_passive_scan(const char* domain) {
    Nob_Cmd cmd = {0};
    Nob_String_Builder sb = {0};
    nob_sb_append_cstr(&sb, OUTPUT_FOLDER);
    
    if (!nob_mkdir_if_not_exists(OUTPUT_FOLDER"amass")) return 1;
    nob_sb_append_cstr(&sb, "amass/");
    nob_sb_append_cstr(&sb, domain); 
    nob_sb_append_cstr(&sb, ".txt");
            
    printf("Domain %s\n", domain);
    // nob_cmd_append(&cmd, "amass", "enum", "-passive", "-d", domain, "-o", sb.items);
    nob_cmd_append(&cmd, "amass", "enum", "-passive", "-d", domain, "|", "grep", "-Eo", "\'^[a-zA-Z0-9.-]+\\.ine\\.com\'", "|", "anew", sb.items);

    print_command(cmd);
    // if (!nob_cmd_run_sync_and_reset(&cmd)) return false;
    return true;
}

char* combine_string(const char* a, const char* b)
{
    Nob_String_Builder sb = {0};
    nob_sb_append_cstr(&sb, a);
    nob_sb_append_cstr(&sb, b);

    return sb.items;
}

bool create_folder_and_output_file(char* target)
{
    // Create parent folder
    Nob_String_Builder sb = {0};
    nob_sb_append_cstr(&sb, OUTPUT_FOLDER);
    nob_sb_append_cstr(&sb, target);
    if (!nob_mkdir_if_not_exists(sb.items)) return false;

    // Setup waf detect
    char* wafw00f_folder = combine_string(sb.items, "/wafw00f");
    char* wafw00f_output_file = combine_string(wafw00f_folder, "/waf.txt");
    if (!nob_mkdir_if_not_exists(wafw00f_folder)) return false;
    if (!nob_create_file(wafw00f_output_file)) return false;
    nob_da_append(&output_file_list, wafw00f_output_file);

    // Setup subfinder
    char* subfinder_folder = combine_string(sb.items, "/subfinder");
    char* subfinder_output_file = combine_string(subfinder_folder, "/subfinder.txt");
    if (!nob_mkdir_if_not_exists(subfinder_folder)) return false;
    if (!nob_create_file(subfinder_output_file)) return false;
    nob_da_append(&output_file_list, subfinder_output_file);

    // if (!nob_mkdir_if_not_exists(combine_string(sb.items, "/amass"))) return false;
    // if (!nob_mkdir_if_not_exists(combine_string(sb.items, "/"))) return false;
    // if (!nob_mkdir_if_not_exists(combine_string(sb.items, "/"))) return false;
    nob_sb_free(sb);
    return true;
}

bool waf_detect (const char* target, const char* output_filepath)
{
    Nob_Cmd cmd = {0};
    nob_cmd_append(&cmd, "wafw00f", target, "-o", output_filepath);
    if (!nob_cmd_run_sync_and_reset(&cmd)) return false;
    return true;
}

int main(int argc, char **argv)
{
    char* path = "domain.txt";
    NOB_GO_REBUILD_URSELF(argc, argv);
    if (!nob_mkdir_if_not_exists(OUTPUT_FOLDER)) return 1;
    Nob_String_Array lines;

    if (nob_readline_file(path, &lines)) {
        for (size_t i = 0; i < lines.count; ++i) {
            printf("Target %zu: %s\n", i + 1, lines.items[i]);
            char* target = lines.items[i] + 2;

            // Setup folder and output file
            create_folder_and_output_file(target);

            // WAF detection with wafw00f
            waf_detect(target, output_file_list.items[0]);
        }
    }

    return 0;
}