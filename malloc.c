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

#if MULTI_BUF
/* queue */
TAILQ_HEAD(tailhead, alloc_buf) head = TAILQ_HEAD_INITIALIZER(head);
struct tailhead *headp;                         /* Tail queue head. */
struct alloc_buf {
    TAILQ_ENTRY(alloc_buf) alloc_bufs;          /* Tail queue. */
    void *addr_p;
    char addr_str[64];
    unsigned long len; 
	struct sysctl_oid *oid;
} *tmp_alloc_buf;
static unsigned long num_bufs = 0;
#endif

/* sysctls */
static struct sysctl_ctx_list clist;
static struct sysctl_oid *poid, *buf_poid;

/* sysctl procedures */
static void
sysctl_update_addr(void *p)
{
    addr_p = p;
    snprintf(addr_str, sizeof(addr_str), "0x%016lx", (unsigned long)addr_p);
}
#if MULTI_BUF
static void
sysctl_add_buf(struct alloc_buf *buf) {
	char buf_idx_str[64] = "";
	
	snprintf(buf_idx_str, sizeof(buf_idx_str), "%lu", num_bufs);
	
	buf->oid = SYSCTL_ADD_NODE(&clist,
		SYSCTL_CHILDREN(buf_poid), OID_AUTO,
		buf_idx_str, 0, 0, "buf root");
	SYSCTL_ADD_STRING(&clist, SYSCTL_CHILDREN(buf->oid), OID_AUTO, 
		"addr", CTLFLAG_RD | CTLFLAG_MPSAFE, 
		buf->addr_str, sizeof(buf->addr_str), "buf addr");
	SYSCTL_ADD_ULONG(&clist, SYSCTL_CHILDREN(buf->oid), OID_AUTO,
		"len", CTLFLAG_RW, &buf->len, "buf len");
	num_bufs++;
}

static void
sysctl_remove_buf(struct alloc_buf *buf) {
	sysctl_remove_oid(buf->oid, 1, 1);
	num_bufs--;
}

static void
update_buf(struct alloc_buf *buf, void *addr_p, unsigned long len) {
	buf->addr_p = addr_p;
	snprintf(buf->addr_str, sizeof(buf->addr_str), "0x%016lx", (unsigned long)addr_p);
	buf->len = len;
}
#endif
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
		tmp_alloc_buf = malloc(sizeof(struct alloc_buf), M_KLDMALLOCBUF, M_NOWAIT);
		if (!tmp_alloc_buf)
			goto alloc_ret;
		p = malloc(alloc_size, M_KLDMALLOCBUF, M_NOWAIT);
		if (!p) {
			free(tmp_alloc_buf, M_KLDMALLOCBUF);
			goto alloc_ret;
		}
		TAILQ_INSERT_HEAD(&head, tmp_alloc_buf, alloc_bufs);
		update_buf(tmp_alloc_buf, p, alloc_size);
		sysctl_add_buf(tmp_alloc_buf);
		allocated += alloc_size;
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
		while (free_siz > 0 && allocated > free_siz) {
			tmp_alloc_buf = TAILQ_LAST(&head, tailhead);
			if (!tmp_alloc_buf) {
				printf("Malloc: no buf found to free %lu!\n", free_siz);
				goto free_ret;
			}
			if (tmp_alloc_buf->len > free_siz) {
				size = tmp_alloc_buf->len - free_siz;
				p = realloc(tmp_alloc_buf->addr_p, size, M_KLDMALLOCBUF, M_NOWAIT);
				if (!p) {
					printf("Malloc: realloc failed\n");
					goto free_ret;
				} else {
					allocated -= free_siz;
					free_siz = 0;
					update_buf(tmp_alloc_buf, p, size);
				}
			} else {
				allocated -= tmp_alloc_buf->len;
				free_siz -= tmp_alloc_buf->len;
				free(tmp_alloc_buf->addr_p, M_KLDMALLOCBUF);
				sysctl_remove_buf(tmp_alloc_buf);
				TAILQ_REMOVE(&head, tmp_alloc_buf, alloc_bufs);
				free(tmp_alloc_buf, M_KLDMALLOCBUF);
			}
		}
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
#if MULTI_BUF
			buf_poid = SYSCTL_ADD_NODE(&clist,
                    SYSCTL_CHILDREN(poid), OID_AUTO,
                    "buf", 0, 0, "buf root");
#endif
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



