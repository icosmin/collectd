/**
 * collectd - src/processes.c
 * Copyright (C) 2005       Lyonel Vincent
 * Copyright (C) 2006-2010  Florian octo Forster
 * Copyright (C) 2008       Oleg King
 * Copyright (C) 2009       Sebastian Harl
 * Copyright (C) 2009       Andrés J. Díaz
 * Copyright (C) 2009       Manuel Sanmartin
 * Copyright (C) 2010       Clément Stenac
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Lyonel Vincent <lyonel at ezix.org>
 *   Florian octo Forster <octo at verplant.org>
 *   Oleg King <king2 at kaluga.ru>
 *   Sebastian Harl <sh at tokkee.org>
 *   Andrés J. Díaz <ajdiaz at connectical.com>
 *   Manuel Sanmartin
 *   Clément Stenac <clement.stenac at diwi.org>
 **/

#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "configfile.h"


#include <procfs.h>
#include <dirent.h>


#include <regex.h>


#ifndef ARG_MAX
#define ARG_MAX 4096
#endif

typedef struct procstat_entry_s {
    unsigned long id;
    unsigned long age;

    unsigned long num_proc;
    unsigned long num_lwp;
    unsigned long vmem_size;
    unsigned long vmem_rss;
    unsigned long vmem_data;
    unsigned long vmem_code;
    unsigned long stack_size;

    unsigned long vmem_minflt;
    unsigned long vmem_majflt;
    derive_t vmem_minflt_counter;
    derive_t vmem_majflt_counter;

    unsigned long cpu_user;
    unsigned long cpu_system;
    derive_t cpu_user_counter;
    derive_t cpu_system_counter;

    /* io data */
    derive_t io_rchar;
    derive_t io_wchar;
    derive_t io_syscr;
    derive_t io_syscw;

    struct procstat_entry_s *next;
} procstat_entry_t;

#define PROCSTAT_NAME_LEN 256

typedef struct procstat {
    char name[PROCSTAT_NAME_LEN];
    regex_t *re;

    unsigned long num_proc;
    unsigned long num_lwp;
    unsigned long vmem_size;
    unsigned long vmem_rss;
    unsigned long vmem_data;
    unsigned long vmem_code;
    unsigned long stack_size;
    char state;

    derive_t vmem_minflt_counter;
    derive_t vmem_majflt_counter;

    derive_t cpu_user_counter;
    derive_t cpu_system_counter;

    /* io data */
    derive_t io_rchar;
    derive_t io_wchar;
    derive_t io_syscr;
    derive_t io_syscw;

    struct procstat *next;
    struct procstat_entry_s *instances;
} procstat_t;

static procstat_t *list_head_g = NULL;


static int pagesize;


/* put name of process from config to list_head_g tree
   list_head_g is a list of 'procstat_t' structs with
   processes names we want to watch */
static void ps_list_register(const char *name, const char *regexp) {
    procstat_t *new;
    procstat_t *ptr;
    int status;

    new = (procstat_t *) malloc(sizeof (procstat_t));
    if (new == NULL) {
        ERROR("processes plugin: ps_list_register: malloc failed.");
        return;
    }
    memset(new, 0, sizeof (procstat_t));
    sstrncpy(new->name, name, sizeof (new->name));


    if (regexp != NULL) {
        DEBUG("ProcessMatch: adding \"%s\" as criteria to process %s.", regexp, name);
        new->re = (regex_t *) malloc(sizeof (regex_t));
        if (new->re == NULL) {
            ERROR("processes plugin: ps_list_register: malloc failed.");
            sfree(new);
            return;
        }

        status = regcomp(new->re, regexp, REG_EXTENDED | REG_NOSUB);
        if (status != 0) {
            DEBUG("ProcessMatch: compiling the regular expression \"%s\" failed.", regexp);
            sfree(new->re);
            return;
        }
    }

    for (ptr = list_head_g; ptr != NULL; ptr = ptr->next) {
        if (strcmp(ptr->name, name) == 0) {
            WARNING("processes plugin: You have configured more "
                    "than one `Process' or "
                    "`ProcessMatch' with the same name. "
                    "All but the first setting will be "
                    "ignored.");
            sfree(new->re);
            sfree(new);
            return;
        }

        if (ptr->next == NULL)
            break;
    }

    if (ptr == NULL)
        list_head_g = new;
    else
        ptr->next = new;
} /* void ps_list_register */

/* try to match name against entry, returns 1 if success */
static int ps_list_match(const char *name, const char *cmdline, procstat_t *ps) {

    if (ps->re != NULL) {
        int status;
        const char *str;

        str = cmdline;
        if ((str == NULL) || (str[0] == 0))
            str = name;

        assert(str != NULL);

        status = regexec(ps->re, str,
                /* nmatch = */ 0,
                /* pmatch = */ NULL,
                /* eflags = */ 0);
        if (status == 0)
            return (1);
    } else

        if (strcmp(ps->name, name) == 0)
        return (1);

    return (0);
} /* int ps_list_match */

/* add process entry to 'instances' of process 'name' (or refresh it) */
static void ps_list_add(const char *name, const char *cmdline, procstat_entry_t *entry) {
    procstat_t *ps;
    procstat_entry_t *pse;

    if (entry->id == 0)
        return;

    for (ps = list_head_g; ps != NULL; ps = ps->next) {
        if ((ps_list_match(name, cmdline, ps)) == 0)
            continue;

        for (pse = ps->instances; pse != NULL; pse = pse->next)
            if ((pse->id == entry->id) || (pse->next == NULL))
                break;

        if ((pse == NULL) || (pse->id != entry->id)) {
            procstat_entry_t *new;

            new = (procstat_entry_t *) malloc(sizeof (procstat_entry_t));
            if (new == NULL)
                return;
            memset(new, 0, sizeof (procstat_entry_t));
            new->id = entry->id;

            if (pse == NULL)
                ps->instances = new;
            else
                pse->next = new;

            pse = new;
        }

        pse->age = 0;
        pse->num_proc = entry->num_proc;
        pse->num_lwp = entry->num_lwp;
        pse->vmem_size = entry->vmem_size;
        pse->vmem_rss = entry->vmem_rss;
        pse->vmem_data = entry->vmem_data;
        pse->vmem_code = entry->vmem_code;
        pse->stack_size = entry->stack_size;
        pse->io_rchar = entry->io_rchar;
        pse->io_wchar = entry->io_wchar;
        pse->io_syscr = entry->io_syscr;
        pse->io_syscw = entry->io_syscw;

        ps->num_proc += pse->num_proc;
        ps->num_lwp += pse->num_lwp;
        ps->vmem_size += pse->vmem_size;
        ps->vmem_rss += pse->vmem_rss;
        ps->vmem_data += pse->vmem_data;
        ps->vmem_code += pse->vmem_code;
        ps->stack_size += pse->stack_size;

        ps->io_rchar += ((pse->io_rchar == -1) ? 0 : pse->io_rchar);
        ps->io_wchar += ((pse->io_wchar == -1) ? 0 : pse->io_wchar);
        ps->io_syscr += ((pse->io_syscr == -1) ? 0 : pse->io_syscr);
        ps->io_syscw += ((pse->io_syscw == -1) ? 0 : pse->io_syscw);

        if ((entry->vmem_minflt_counter == 0)
                && (entry->vmem_majflt_counter == 0)) {
            pse->vmem_minflt_counter += entry->vmem_minflt;
            pse->vmem_minflt = entry->vmem_minflt;

            pse->vmem_majflt_counter += entry->vmem_majflt;
            pse->vmem_majflt = entry->vmem_majflt;
        } else {
            if (entry->vmem_minflt_counter < pse->vmem_minflt_counter) {
                pse->vmem_minflt = entry->vmem_minflt_counter
                        + (ULONG_MAX - pse->vmem_minflt_counter);
            } else {
                pse->vmem_minflt = entry->vmem_minflt_counter - pse->vmem_minflt_counter;
            }
            pse->vmem_minflt_counter = entry->vmem_minflt_counter;

            if (entry->vmem_majflt_counter < pse->vmem_majflt_counter) {
                pse->vmem_majflt = entry->vmem_majflt_counter
                        + (ULONG_MAX - pse->vmem_majflt_counter);
            } else {
                pse->vmem_majflt = entry->vmem_majflt_counter - pse->vmem_majflt_counter;
            }
            pse->vmem_majflt_counter = entry->vmem_majflt_counter;
        }

        ps->vmem_minflt_counter += pse->vmem_minflt;
        ps->vmem_majflt_counter += pse->vmem_majflt;

        if ((entry->cpu_user_counter == 0)
                && (entry->cpu_system_counter == 0)) {
            pse->cpu_user_counter += entry->cpu_user;
            pse->cpu_user = entry->cpu_user;

            pse->cpu_system_counter += entry->cpu_system;
            pse->cpu_system = entry->cpu_system;
        } else {
            if (entry->cpu_user_counter < pse->cpu_user_counter) {
                pse->cpu_user = entry->cpu_user_counter
                        + (ULONG_MAX - pse->cpu_user_counter);
            } else {
                pse->cpu_user = entry->cpu_user_counter - pse->cpu_user_counter;
            }
            pse->cpu_user_counter = entry->cpu_user_counter;

            if (entry->cpu_system_counter < pse->cpu_system_counter) {
                pse->cpu_system = entry->cpu_system_counter
                        + (ULONG_MAX - pse->cpu_system_counter);
            } else {
                pse->cpu_system = entry->cpu_system_counter - pse->cpu_system_counter;
            }
            pse->cpu_system_counter = entry->cpu_system_counter;
        }

        ps->cpu_user_counter += pse->cpu_user;
        ps->cpu_system_counter += pse->cpu_system;
    }
}

/* remove old entries from instances of processes in list_head_g */
static void ps_list_reset(void) {
    procstat_t *ps;
    procstat_entry_t *pse;
    procstat_entry_t *pse_prev;

    for (ps = list_head_g; ps != NULL; ps = ps->next) {
        ps->num_proc = 0;
        ps->num_lwp = 0;
        ps->vmem_size = 0;
        ps->vmem_rss = 0;
        ps->vmem_data = 0;
        ps->vmem_code = 0;
        ps->stack_size = 0;
        ps->io_rchar = -1;
        ps->io_wchar = -1;
        ps->io_syscr = -1;
        ps->io_syscw = -1;

        pse_prev = NULL;
        pse = ps->instances;
        while (pse != NULL) {
            if (pse->age > 10) {
                DEBUG("Removing this procstat entry cause it's too old: "
                        "id = %lu; name = %s;",
                        pse->id, ps->name);

                if (pse_prev == NULL) {
                    ps->instances = pse->next;
                    free(pse);
                    pse = ps->instances;
                } else {
                    pse_prev->next = pse->next;
                    free(pse);
                    pse = pse_prev->next;
                }
            } else {
                pse->age++;
                pse_prev = pse;
                pse = pse->next;
            }
        } /* while (pse != NULL) */
    } /* for (ps = list_head_g; ps != NULL; ps = ps->next) */
}

/* put all pre-defined 'Process' names from config to list_head_g tree */
static int ps_config(oconfig_item_t *ci) {
    int i;

    printf("Entering ps_config function\n");
    for (i = 0; i < ci->children_num; ++i) {
        oconfig_item_t *c = ci->children + i;

        if (strcasecmp(c->key, "Process") == 0) {
            if ((c->values_num != 1)
                    || (OCONFIG_TYPE_STRING != c->values[0].type)) {
                ERROR("processes plugin: `Process' expects exactly "
                        "one string argument (got %i).",
                        c->values_num);
                continue;
            }

            if (c->children_num != 0) {
                WARNING("processes plugin: the `Process' config option "
                        "does not expect any child elements -- ignoring "
                        "content (%i elements) of the <Process '%s'> block.",
                        c->children_num, c->values[0].value.string);
            }

            ps_list_register(c->values[0].value.string, NULL);
        } else if (strcasecmp(c->key, "ProcessMatch") == 0) {
            if ((c->values_num != 2)
                    || (OCONFIG_TYPE_STRING != c->values[0].type)
                    || (OCONFIG_TYPE_STRING != c->values[1].type)) {
                ERROR("processes plugin: `ProcessMatch' needs exactly "
                        "two string arguments (got %i).",
                        c->values_num);
                continue;
            }

            if (c->children_num != 0) {
                WARNING("processes plugin: the `ProcessMatch' config option "
                        "does not expect any child elements -- ignoring "
                        "content (%i elements) of the <ProcessMatch '%s' '%s'> "
                        "block.", c->children_num, c->values[0].value.string,
                        c->values[1].value.string);
            }

            ps_list_register(c->values[0].value.string,
                    c->values[1].value.string);
        } else {
            ERROR("processes plugin: The `%s' configuration option is not "
                    "understood and will be ignored.", c->key);
            continue;
        }
    }

    return (0);
}

static int ps_init(void) {
    printf("Entering ps_init function\n");

    pagesize = getpagesize();


    return (0);
} /* int ps_init */

/* submit global state (e.g.: qty of zombies, running, etc..) */
static void ps_submit_state(const char *state, double value) {
    value_t values[1];
    value_list_t vl = VALUE_LIST_INIT;

    values[0].gauge = value;

    vl.values = values;
    vl.values_len = 1;
    sstrncpy(vl.host, hostname_g, sizeof (vl.host));
    sstrncpy(vl.plugin, "processes", sizeof (vl.plugin));
    sstrncpy(vl.plugin_instance, "", sizeof (vl.plugin_instance));
    sstrncpy(vl.type, "ps_state", sizeof (vl.type));
    sstrncpy(vl.type_instance, state, sizeof (vl.type_instance));

    plugin_dispatch_values(&vl);
}

/* submit info about specific process (e.g.: memory taken, cpu usage, etc..) */
static void ps_submit_proc_list(procstat_t *ps) {
    value_t values[2];
    value_list_t vl = VALUE_LIST_INIT;

    vl.values = values;
    vl.values_len = 2;
    sstrncpy(vl.host, hostname_g, sizeof (vl.host));
    sstrncpy(vl.plugin, "processes", sizeof (vl.plugin));
    sstrncpy(vl.plugin_instance, ps->name, sizeof (vl.plugin_instance));

    sstrncpy(vl.type, "ps_vm", sizeof (vl.type));
    vl.values[0].gauge = ps->vmem_size;
    vl.values_len = 1;
    plugin_dispatch_values(&vl);

    sstrncpy(vl.type, "ps_rss", sizeof (vl.type));
    vl.values[0].gauge = ps->vmem_rss;
    vl.values_len = 1;
    plugin_dispatch_values(&vl);

    sstrncpy(vl.type, "ps_data", sizeof (vl.type));
    vl.values[0].gauge = ps->vmem_data;
    vl.values_len = 1;
    plugin_dispatch_values(&vl);

    sstrncpy(vl.type, "ps_code", sizeof (vl.type));
    vl.values[0].gauge = ps->vmem_code;
    vl.values_len = 1;
    plugin_dispatch_values(&vl);

    sstrncpy(vl.type, "ps_stacksize", sizeof (vl.type));
    vl.values[0].gauge = ps->stack_size;
    vl.values_len = 1;
    plugin_dispatch_values(&vl);

    sstrncpy(vl.type, "ps_cputime", sizeof (vl.type));
    vl.values[0].derive = ps->cpu_user_counter;
    vl.values[1].derive = ps->cpu_system_counter;
    vl.values_len = 2;
    plugin_dispatch_values(&vl);

    sstrncpy(vl.type, "ps_count", sizeof (vl.type));
    vl.values[0].gauge = ps->num_proc;
    vl.values[1].gauge = ps->num_lwp;
    vl.values_len = 2;
    plugin_dispatch_values(&vl);

    sstrncpy(vl.type, "ps_pagefaults", sizeof (vl.type));
    vl.values[0].derive = ps->vmem_minflt_counter;
    vl.values[1].derive = ps->vmem_majflt_counter;
    vl.values_len = 2;
    plugin_dispatch_values(&vl);

    if ((ps->io_rchar != -1) && (ps->io_wchar != -1)) {
        sstrncpy(vl.type, "ps_disk_octets", sizeof (vl.type));
        vl.values[0].derive = ps->io_rchar;
        vl.values[1].derive = ps->io_wchar;
        vl.values_len = 2;
        plugin_dispatch_values(&vl);
    }

    if ((ps->io_syscr != -1) && (ps->io_syscw != -1)) {
        sstrncpy(vl.type, "ps_disk_ops", sizeof (vl.type));
        vl.values[0].derive = ps->io_syscr;
        vl.values[1].derive = ps->io_syscw;
        vl.values_len = 2;
        plugin_dispatch_values(&vl);
    }

    DEBUG("name = %s; num_proc = %lu; num_lwp = %lu; "
            "vmem_size = %lu; vmem_rss = %lu; vmem_data = %lu; "
            "vmem_code = %lu; "
            "vmem_minflt_counter = %"PRIi64"; vmem_majflt_counter = %"PRIi64"; "
            "cpu_user_counter = %"PRIi64"; cpu_system_counter = %"PRIi64"; "
            "io_rchar = %"PRIi64"; io_wchar = %"PRIi64"; "
            "io_syscr = %"PRIi64"; io_syscw = %"PRIi64";",
            ps->name, ps->num_proc, ps->num_lwp,
            ps->vmem_size, ps->vmem_rss,
            ps->vmem_data, ps->vmem_code,
            ps->vmem_minflt_counter, ps->vmem_majflt_counter,
            ps->cpu_user_counter, ps->cpu_system_counter,
            ps->io_rchar, ps->io_wchar, ps->io_syscr, ps->io_syscw);
} /* void ps_submit_proc_list */


static char *ps_get_cmdline(pid_t pid) {
    char f_psinfo[64];
    char *buffer;
    psinfo_t *myInfo;

    snprintf(f_psinfo, sizeof (f_psinfo), "/proc/%i/psinfo", pid);

    buffer = malloc(sizeof (psinfo_t));
    read_file_contents(f_psinfo, buffer, sizeof (psinfo_t));
    buffer[sizeof (psinfo_t)] = 0;
    myInfo = (psinfo_t *) buffer;

    sstrncpy(buffer, myInfo->pr_psargs, sizeof (myInfo->pr_psargs));
    free(myInfo);
    return buffer;
}

static int psrp(int pid, procstat_t *ps, char *state) {

    printf("Inside ps_read_process\n");
    char filename[64];
    char f_psinfo[64], f_usage[64];
    int i;
    char *buffer;   
        

    pstatus_t *myStatus;
    psinfo_t *myInfo;
    prusage_t *myUsage;

    snprintf(filename, sizeof (filename), "/proc/%i/status", pid);
    snprintf(f_psinfo, sizeof (f_psinfo), "/proc/%i/psinfo", pid);
    snprintf(f_usage, sizeof (f_usage), "/proc/%i/usage", pid);
  

    buffer = malloc(sizeof (pstatus_t));
    read_file_contents(filename, buffer, sizeof (pstatus_t));
    myStatus = (pstatus_t *) buffer;

    buffer = malloc(sizeof (psinfo_t));
    read_file_contents(f_psinfo, buffer, sizeof (psinfo_t));
    buffer[sizeof (psinfo_t)] = 0;
    myInfo = (psinfo_t *) buffer;

    buffer = malloc(sizeof (prusage_t));
    read_file_contents(f_usage, buffer, sizeof (prusage_t));
    myUsage = (prusage_t *) buffer;

    printf("myInfo->pr_fname=%s\n", myInfo->pr_fname);
    sstrncpy(ps->name, myInfo->pr_fname, sizeof (myInfo->pr_fname));    
    printf("Mark 2\n");
    ps->num_lwp = myStatus->pr_nlwp;
    if (myInfo->pr_wstat != 0) {
        ps->num_proc = 0;
        ps->num_lwp = 0;
        *state = (char) 'Z';        
        return(0);
    } else {
        ps->num_proc = 1;
        ps->num_lwp = myInfo->pr_nlwp;
    }

    /*
     * Convert system time and user time from nanoseconds to microseconds
     * for compatibility with the linux module
     */
    ps->cpu_system_counter = myStatus -> pr_stime.tv_nsec / 1000;
    ps->cpu_user_counter = myStatus -> pr_utime.tv_nsec / 1000;
     
    /*
     * Convert rssize from KB to bytes to be consistent w/ the linux module
     */
    ps->vmem_rss = myInfo->pr_rssize * 1024;
    ps->vmem_size = myInfo->pr_size * 1024;
    ps->vmem_minflt_counter = myUsage->pr_minf;
    ps->vmem_majflt_counter = myUsage->pr_majf;

    /*
     * TODO: Data and code segment calculations for Solaris
     */

    ps->vmem_data = -1;
    ps->vmem_code = -1;
    ps->stack_size = myStatus->pr_stksize;

    /*
     * Calculating input/ouput chars
     * Formula used is total chars / total blocks => chars/block
     * then convert input/output blocks to chars
     */


    ulong_t tot_chars = myUsage->pr_ioch;
    ulong_t tot_blocks = myUsage->pr_inblk + myUsage->pr_oublk;
    ulong_t chars_per_block = 1;
    if (tot_blocks != 0)
        chars_per_block = tot_chars / tot_blocks;
    ps->io_rchar = myUsage->pr_inblk * chars_per_block;
    ps->io_wchar = myUsage->pr_oublk * chars_per_block;
    ps->io_syscr = myUsage->pr_sysc;
    ps->io_syscw = myUsage->pr_sysc;


    /*
     * TODO: Find way of setting BLOCKED and PAGING status
     */

    *state = (char) 'R';
    if (myStatus->pr_flags & PR_ASLEEP)
        *state = (char) 'S';
    else if (myStatus->pr_flags & PR_STOPPED)
        *state = (char) 'T';

    free(myStatus);
    free(myInfo);
    free(myUsage);
    printf("Mark 100\n");

    return(0);
}


/* do actual readings from kernel */

static int ps_read(void) {    
    int running = 0;
    int sleeping = 0;
    int zombies = 0;
    int stopped = 0;
    int paging = 0;
    int blocked = 0;
    struct dirent *ent;
    DIR *proc;
    int pid;
/*
    char cmdline[ARG_MAX];
*/

    int status;
    struct procstat ps;
    procstat_entry_t pse; 
    char state;
/*
    unsigned long fork_rate;
*/

    printf("Mark ps_ptr\n");
/*
    procstat_t *ps_ptr;
*/
    
    printf("Reset list 0\n");
    ps_list_reset();    
    printf("Reset list\n");


    proc = opendir("/proc");
    if (proc == NULL) {        
        return (-1);
    }

    while ((ent = readdir(proc)) != NULL) {
            if (!isdigit(ent->d_name[0]))
                continue;

            if ((pid = atoi(ent->d_name)) < 1)                
                continue;       
            
            status = psrp(pid, &ps, &state);
            if (status != 0) {
                DEBUG("ps_read_process failed: %i", status);                
                continue;
            }
            pse.id = pid;
            pse.age = 0;

            pse.num_proc = ps.num_proc;
            pse.num_lwp = ps.num_lwp;
            pse.vmem_size = ps.vmem_size;
            pse.vmem_rss = ps.vmem_rss;
            pse.vmem_data = ps.vmem_data;
            pse.vmem_code = ps.vmem_code;
            pse.stack_size = ps.stack_size;

            pse.vmem_minflt = 0;
            pse.vmem_minflt_counter = ps.vmem_minflt_counter;
            pse.vmem_majflt = 0;
            pse.vmem_majflt_counter = ps.vmem_majflt_counter;

            pse.cpu_user = 0;
            pse.cpu_user_counter = ps.cpu_user_counter;
            pse.cpu_system = 0;
            pse.cpu_system_counter = ps.cpu_system_counter;

            pse.io_rchar = ps.io_rchar;
            pse.io_wchar = ps.io_wchar;
            pse.io_syscr = ps.io_syscr;
            pse.io_syscw = ps.io_syscw;
            
            switch (state) {
                case 'R': running++;
                    break;
                case 'S': sleeping++;
                    break;
                case 'D': blocked++;
                    break;
                case 'Z': zombies++;
                    break;
                case 'T': stopped++;
                    break;
                case 'W': paging++;
                    break;
            }
            
            ps_list_add(ps.name, "", &pse);
            
    } // while()
    closedir(proc);
    
    return(0);
} /* int ps_read */

void module_register(void) {
    plugin_register_complex_config("processes", ps_config);
    plugin_register_init("processes", ps_init);    
    plugin_register_read("processes", ps_read);        
} /* void module_register */
