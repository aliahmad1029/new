#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>  /* uprintf */
#include <sys/errno.h>
#include <sys/param.h>  /* defines used in kernel.h */
#include <sys/kernel.h> /* types used in module initialization */

#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/malloc.h>

/* debug */
//#define DEBUG_STRTOL
#define MULTI_BUF 1

/* global variables */
static unsigned long allocated = 0; 
static unsigned long alloc_size = 0;
static unsigned long free_siz = 0;
static void *addr_p;
static char addr_str[64] = "";
static char alloc_str[64] = "";
static char free_str[64] = "";

/* malloc */
MALLOC_DECLARE(M_KLDMALLOCBUF);
MALLOC_DEFINE(M_KLDMALLOCBUF, "kld malloc", "Buffers for kld malloc");

/* queue */
TAILQ_HEAD(tailhead, alloc_buf) head = TAILQ_HEAD_INITIALIZER(head);
struct tailhead *headp;                         /* Tail queue head. */
struct alloc_buf {
    TAILQ_ENTRY(alloc_buf) alloc_bufs;          /* Tail queue. */
    void *addr_p;
    char addr_str[64];
    unsigned long len; 
} *tmp_alloc_buf;

/* sysctls */
static struct sysctl_ctx_list clist;
static struct sysctl_oid *poid;

/* sysctl procedures */
static void
sysctl_update_addr(void *p)
{
    addr_p = p;
    snprintf(addr_str, sizeof(addr_str), "0x%016lx", (unsigned long)addr_p);
}

/* if error or non-positive value, return 0 */
static long
size_strtoul(char *str)
{
    char *end;
    long base = 1;
    long ret;

    if ((end = strchr(str, 'k')) || (end = strchr(str, 'K')))
        base = 1 << 10;
    else if ((end = strchr(str, 'm')) || (end = strchr(str, 'M')))
        base = 1 << 20;
    else if ((end = strchr(str, 'g')) || (end = strchr(str, 'G')))
        base = 1 << 30;
    end = '\0';

    ret = strtol(str, NULL, 10);
#ifdef DEBUG_STRTOL
    printf("%s: strtol ret %ld base %ld \n", __func__, ret, base);
#endif
    if (ret == EINVAL || ret == ERANGE || ret < 0)
        return 0;
    else
        ret *= base;
    if (ret > 0)
        return ((unsigned long)ret);
    else
        return 0;
}

static int
sysctl_alloc_procedure(SYSCTL_HANDLER_ARGS)
{
    int error = 0;
    void *p = NULL;
    unsigned long ret = 0;
       
    error = sysctl_handle_string(oidp, alloc_str, sizeof(alloc_str), req);
    if (error) {
        printf("Malloc: sysctl_handle_int failed\n");
        goto alloc_ret;
    }
    
    if (strcmp(alloc_str,""))
        ret = size_strtoul(alloc_str);
    alloc_size = ret;

    if (alloc_size) {
#if MULTI_BUF
#else
        if (allocated)
            p = realloc(addr_p, (allocated + alloc_size), M_KLDMALLOCBUF, M_NOWAIT);
        else {
            p = malloc(alloc_size, M_KLDMALLOCBUF, M_NOWAIT);
        }
        if (!p)
            printf("Malloc: allocate failed\n");
        else {
            allocated += alloc_size;
            sysctl_update_addr(p);
            printf("Malloc: allocate %lu at %p, allocated size %lu\n",
                    alloc_size, addr_p, allocated);
        }
#endif
    }
alloc_ret:
    alloc_str[0] = '\0';
    return error;
}

static int
sysctl_free_procedure(SYSCTL_HANDLER_ARGS)
{
    int error = 0;
    unsigned long size = 0;
    void *p = NULL;
    unsigned long ret = 0;
    
    error = sysctl_handle_string(oidp, free_str, sizeof(free_str), req);
    if (error) {
        printf("Malloc: sysctl_handle_int failed\n");
        goto free_ret;
    }

    if (strcmp(free_str,""))
        ret = size_strtoul(free_str);
    else if (!strcmp(free_str,"all"))
        ret = allocated;
    free_siz = ret;

    if (free_siz) {
#if MULTI_BUF
#else
        if (allocated > free_siz) {
            size = allocated - free_siz;
            p = realloc(addr_p, size, M_KLDMALLOCBUF, M_NOWAIT);
            
            if (!p)
                printf("Malloc: realloc failed\n");
            else {
                allocated = size;
                sysctl_update_addr(p);
                printf("Malloc: free %lu success at %p, allocated size %lu\n",
                    free_siz, addr_p, allocated);
            }
        } else if (allocated == free_siz) {
            free(addr_p, M_KLDMALLOCBUF);
            allocated = 0;
            sysctl_update_addr(NULL);
            printf("Malloc: free all allocated size\n");
        } else {
            printf("Malloc: larger than allocated size\n");
        }
#endif
    }
#endif
free_ret:
    free_str[0] = '\0';
    return error;
}


static int
malloc_modevent(module_t mod __unused, int event, void *arg __unused)
{
    int error = 0;

    switch (event) {
        case MOD_LOAD:            
            sysctl_ctx_init(&clist);

            poid = SYSCTL_ADD_NODE(&clist,
                    SYSCTL_STATIC_CHILDREN(/* tree top */), OID_AUTO,
                    "malloc", 0, 0, "malloc root");
            if (poid == NULL) {
                uprintf("SYSCTL_ADD_NODE failed.\n");
                return (EINVAL);
            }
            SYSCTL_ADD_ULONG(&clist, SYSCTL_CHILDREN(poid), OID_AUTO,
                    "allocated", CTLFLAG_RW, &allocated, "allocated size (in bytes)");
            SYSCTL_ADD_PROC(&clist, SYSCTL_CHILDREN(poid), OID_AUTO,
                    "alloc", CTLTYPE_STRING| CTLFLAG_WR, 0, 0, sysctl_alloc_procedure,
                    "A", "size to alloc");
            SYSCTL_ADD_PROC(&clist, SYSCTL_CHILDREN(poid), OID_AUTO,
                    "free", CTLTYPE_STRING | CTLFLAG_WR, 0, 0, sysctl_free_procedure,
                    "A", "size to free");
            SYSCTL_ADD_STRING(&clist, SYSCTL_CHILDREN(poid), OID_AUTO, 
                    "addr", CTLFLAG_RD | CTLFLAG_MPSAFE, 
                    addr_str, sizeof(addr_str), "allocalted address");
            sysctl_update_addr(NULL);
            uprintf("Malloc module loaded, use 'sysctl malloc' to execute.\n");
            break;
        case MOD_UNLOAD:
#if MULTI_BUF
#else
            if (sysctl_ctx_free(&clist)) {
                uprintf("sysctl_ctx_free failed.\n");
                return (ENOTEMPTY);
            }
            if (addr_p)
                free(addr_p, M_KLDMALLOCBUF);
#endif
            uprintf("Malloc module unloaded.\n");
            break;
        default:
            error = EOPNOTSUPP;
            break;
    }

    return (error);
}

static moduledata_t malloc_mod = {
    "malloc",
    malloc_modevent,
    NULL
};

DECLARE_MODULE(malloc, malloc_mod, SI_SUB_EXEC, SI_ORDER_ANY);



