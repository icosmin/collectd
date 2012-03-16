/* 
 * File:   dev_hash.h
 * Author: Cosmin Ioiart <cioiart at gmail.com>
 *
 * Created on February 2, 2012, 9:52 AM
 */

#ifndef _DEV_HASH_H
#define	_DEV_HASH_H
#include <stdio.h>
#include "uthash.h"
#include "statcommon.h"
#include "acquire.c"
//#include "walkers.c"
#include "acquire_iodevs.c"
#include "dsr.c"
#include "mnt.c"


/*
 * Structure which defines the correspondence between 
 * ssd devices and their nice name (in the form c0t0d0...)
 */
typedef struct io_devices {
    char *ssd_name;
    char *pretty_name;  
    UT_hash_handle hh;
} io_device_t;

static io_device_t *hash_iodevs;

void init_devs();
void add_dev(char *, char *);
io_device_t *find_dev(char *);
void print_devs();
void free_devs();

int iodev_walk(struct iodev_snapshot *);
static void build_hash(void*);



struct snapshot *newss = NULL;

void add_dev(char *ssd, char *devname) {
    io_device_t *d = NULL;
    
    
    d = (io_device_t*)malloc(sizeof(struct io_devices));
    if(d != NULL) {
        d->ssd_name = malloc(strlen(ssd)+1);
        strcpy(d->ssd_name, ssd);
        
        d->pretty_name = malloc(strlen(devname)+1);
        strcpy(d->pretty_name, devname);
        
        HASH_ADD_KEYPTR(hh, hash_iodevs, d->ssd_name, strlen(d->ssd_name), d);
    }
}

io_device_t *find_dev(char *ssd) {
    io_device_t *d = NULL;
    HASH_FIND_STR(hash_iodevs, ssd, d);    
    return d;
}

void free_devs() {
    io_device_t *curr, *tmp;
    HASH_ITER(hh, hash_iodevs, curr, tmp) {
        HASH_DEL(hash_iodevs, curr);
        free(curr->ssd_name);
        free(curr->pretty_name);
        free(curr);
    }
    //free_snapshot(newss);
}

void print_devs() {
    io_device_t *curr, *tmp;
    HASH_ITER(hh, hash_iodevs, curr, tmp) {
        printf("%s, %s\n", curr->ssd_name, curr->pretty_name);
    }
    
}

int iodev_walk(struct iodev_snapshot *d1) {
    int changed = 0;
    
    while (d1) { 
        changed = 1;
        build_hash(d1);
        (void) iodev_walk(d1->is_children);
        d1 = d1->is_next;
    }
           
    return (changed);
}

static void build_hash(void *v1) {
    struct iodev_snapshot *new = (struct iodev_snapshot *)v1;
    char *disk_name, *ssd_name;
    
    if(new == NULL)
        return;
    
    
    disk_name = new->is_pretty ? new->is_pretty: new->is_name;   
    ssd_name = new->is_name;    
    add_dev(ssd_name, disk_name);
}

void init_devs() {
    extern kstat_ctl_t *kc;
    struct iodev_filter df;
    enum snapshot_types types = 549;    
    hash_iodevs = NULL;
    
    
    /* nfs, tape, always shown */
    df.if_allowed_types = 26;
    /* Get stats for all disks */
    df.if_max_iodevs = UNLIMITED_IODEVS;
    df.if_skip_floppy = 0;
    df.if_nr_names = 0;
    
    printf("Debug: Calling acquire_snapshot\n");
    newss = acquire_snapshot(kc, types, &df);
    iodev_walk(newss->s_iodevs);    
    free_snapshot(newss);
    //close_kstat(kc);    
}



#endif	/* _DEV_HASH_H */

