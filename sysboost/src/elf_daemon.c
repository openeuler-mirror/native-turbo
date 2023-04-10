/* SPDX-License-Identifier: MulanPSL-2.0 */
#include <unistd.h>

#include "elf_daemon.h"

void elf_daemon(void)
{
        char line[256];
        char *cpu_model_name = NULL;
        FILE *fp = fopen("/proc/cpuinfo", "r");
        int ret = 0;
        if (fp == NULL) {
                SI_LOG_INFO("open /proc/cpuinfo fault\n");
        }
        while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "model name")) {
                        cpu_model_name = strchr(line, ':');
                        if (cpu_model_name != NULL) {
                                // skip the space after ':'
                                cpu_model_name += 2;
                                break;
                        }
                }
        }
        fclose(fp);

        if (cpu_model_name != NULL && strstr(cpu_model_name, "kunpeng") == NULL) {
                SI_LOG_INFO("This CPU is not Kunpeng\n");
                return;
        }

        ret = execl("/usr/bin/sysboost", "-static", "/usr/bin/sysboost_static_template", "/usr/bin/bash", "/usr/lib64/libtinfo.so", NULL);
        if (ret != 0) {
                SI_LOG_ERR("This CPU is not Kunpeng\n");
                return;
        }
}