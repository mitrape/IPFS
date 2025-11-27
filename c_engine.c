// Build: gcc -O2 -pthread -o c_engine c_engine.c -lblake3
// Run:   ./c_engine /tmp/cengine.sock
//
// Storage layout (relative to cwd):
//   ipfs_store/blocks/<h0h1>/<h2h3>/<fullhash>.bin
//   ipfs_store/manifests/<cid>.json
//
// Hash:  BLAKE3 (32 bytes, hex-encoded)
// Chunk: 256 KiB (must match main.py)

#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <inttypes.h>

#include "blake3.h"   // requires libblake3

#define OP_UPLOAD_START   0x01
#define OP_UPLOAD_CHUNK   0x02
#define OP_UPLOAD_FINISH  0x03
#define OP_UPLOAD_DONE    0x81

// must match main.py
#define OP_DOWNLOAD_START 0x11
#define OP_DOWNLOAD_CHUNK 0x91
#define OP_DOWNLOAD_DONE  0x92

#define STORAGE_ROOT      "ipfs_store"
#define BLOCKS_DIR        STORAGE_ROOT "/blocks"
#define MANIFESTS_DIR     STORAGE_ROOT "/manifests"

#define DEFAULT_CHUNK_SIZE (256 * 1024)

#define NUM_WORKERS 4

static const char* g_sock_path = NULL;

/* ==================== I/O helpers ==================== */

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

ssize_t read_n(int fd, void* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char*)buf + got, n - got);
        if (r == 0) return 0;
        if (r < 0) {
            if (errno == EINTR) continue;
            perror("read");
            return -1;
        }
        got += (size_t)r;
    }
    return (ssize_t)got;
}

int write_all(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            perror("write");
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

int send_frame(int fd, uint8_t op, const void* payload, uint32_t len) {
    uint8_t header[5];
    header[0] = op;
    uint32_t be_len = htonl(len);
    memcpy(header + 1, &be_len, 4);
    if (write_all(fd, header, 5) < 0) return -1;
    if (len && write_all(fd, payload, len) < 0) return -1;
    return 0;
}

/* ==================== FS helpers ==================== */

static int ensure_dir(const char *path) {
    if (mkdir(path, 0777) == 0) return 0;
    if (errno == EEXIST) return 0;
    perror("mkdir");
    return -1;
}

static int ensure_parents_for_path(const char *path) {
    char tmp[PATH_MAX];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char *p = tmp;
    if (*p == '/') p++;
    for (; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (ensure_dir(tmp) < 0) return -1;
            *p = '/';
        }
    }
    return 0;
}

static int write_file_atomic(const char *path, const void *data, size_t len) {
    char tmp_path[PATH_MAX];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    if (ensure_parents_for_path(path) < 0) return -1;

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) { perror("open tmp"); return -1; }

    if (write_all(fd, data, len) < 0) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    if (fsync(fd) < 0) {
        perror("fsync");
        close(fd);
        unlink(tmp_path);
        return -1;
    }

    close(fd);

    if (rename(tmp_path, path) < 0) {
        perror("rename");
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

/* ==================== BLAKE3 hashing ==================== */

static void blake3_hex(const uint8_t *data, size_t len, char out_hex[65]) {
    uint8_t out_bytes[BLAKE3_OUT_LEN];
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, data, len);
    blake3_hasher_finalize(&hasher, out_bytes, BLAKE3_OUT_LEN);

    for (size_t i = 0; i < BLAKE3_OUT_LEN; i++) {
        sprintf(out_hex + 2 * i, "%02x", out_bytes[i]);
    }
    out_hex[2 * BLAKE3_OUT_LEN] = '\0';
}

/* ==================== Paths for blocks/manifests ==================== */

static void make_block_path(const char *hash_hex, char out[PATH_MAX]) {
    char d1[3] = { hash_hex[0], hash_hex[1], '\0' };
    char d2[3] = { hash_hex[2], hash_hex[3], '\0' };
    snprintf(out, PATH_MAX, "%s/%s/%s/%s.bin", BLOCKS_DIR, d1, d2, hash_hex);
}

static void make_manifest_path(const char *cid, char out[PATH_MAX]) {
    snprintf(out, PATH_MAX, "%s/%s.json", MANIFESTS_DIR, cid);
}

/* ==================== Upload state ==================== */

typedef struct {
    uint32_t index;
    uint32_t size;
    char hash[65];
} ChunkMeta;

typedef struct {
    int active;
    char *filename;
    uint64_t total_size;
    uint32_t next_index;
    uint32_t total_chunks;

    ChunkMeta *chunks;
    size_t chunks_cap;

    int pending_tasks;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
} UploadState;

static void upload_state_construct(UploadState *st) {
    memset(st, 0, sizeof(*st));
    pthread_mutex_init(&st->mu, NULL);
    pthread_cond_init(&st->cv, NULL);
}

static void upload_state_reset(UploadState *st) {
    pthread_mutex_lock(&st->mu);
    if (st->filename) {
        free(st->filename);
        st->filename = NULL;
    }
    if (st->chunks) {
        free(st->chunks);
        st->chunks = NULL;
    }
    st->chunks_cap   = 0;
    st->active       = 0;
    st->total_size   = 0;
    st->next_index   = 0;
    st->total_chunks = 0;
    st->pending_tasks = 0;
    pthread_mutex_unlock(&st->mu);
}

static void upload_state_destroy(UploadState *st) {
    upload_state_reset(st);
    pthread_mutex_destroy(&st->mu);
    pthread_cond_destroy(&st->cv);
}

/* ==================== Download state ==================== */

typedef struct {
    uint8_t *data;
    uint32_t size;
    int ready;
    int error;
} DownloadSlot;

typedef struct {
    size_t n_chunks;
    DownloadSlot *slots;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
} DownloadState;

static void download_state_construct(DownloadState *ds, size_t n_chunks) {
    memset(ds, 0, sizeof(*ds));
    ds->n_chunks = n_chunks;
    ds->slots = calloc(n_chunks, sizeof(DownloadSlot));
    pthread_mutex_init(&ds->mu, NULL);
    pthread_cond_init(&ds->cv, NULL);
}

static void download_state_destroy(DownloadState *ds) {
    if (!ds) return;
    pthread_mutex_lock(&ds->mu);
    for (size_t i = 0; i < ds->n_chunks; i++) {
        free(ds->slots[i].data);
    }
    free(ds->slots);
    ds->slots = NULL;
    pthread_mutex_unlock(&ds->mu);
    pthread_mutex_destroy(&ds->mu);
    pthread_cond_destroy(&ds->cv);
}

/* ==================== Thread pool & tasks ==================== */

typedef enum {
    TASK_UPLOAD,
    TASK_DOWNLOAD
} TaskType;

typedef struct Task {
    TaskType type;
    struct Task *next;
    union {
        struct {
            UploadState *st;
            uint32_t index;
            uint8_t *data;
            uint32_t size;
        } upload;
        struct {
            DownloadState *st;
            uint32_t index;
            char hash[65];
        } download;
    } u;
} Task;

static Task *q_head = NULL;
static Task *q_tail = NULL;
static pthread_mutex_t q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  q_cv = PTHREAD_COND_INITIALIZER;

static void enqueue_task(Task *t) {
    pthread_mutex_lock(&q_mu);
    t->next = NULL;
    if (!q_tail) {
        q_head = q_tail = t;
    } else {
        q_tail->next = t;
        q_tail = t;
    }
    pthread_cond_signal(&q_cv);
    pthread_mutex_unlock(&q_mu);
}

/* -------- upload task processing -------- */

static void process_upload_task(Task *t) {
    UploadState *st  = t->u.upload.st;
    uint32_t index   = t->u.upload.index;
    uint8_t *data    = t->u.upload.data;
    uint32_t len     = t->u.upload.size;

    char hash_hex[65];
    blake3_hex(data, len, hash_hex);

    // Store block (content-addressed)
    char path[PATH_MAX];
    make_block_path(hash_hex, path);

    // If file already exists, we do not rewrite (simple dedup).
    // (Refcounting could be added on top of this).
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        // already exists
        close(fd);
    } else {
        if (write_file_atomic(path, data, len) < 0) {
            fprintf(stderr, "Failed to write block %s\n", path);
            // fall through; at least manifest will still reference the hash
        }
    }

    // Store chunk metadata in UploadState
    pthread_mutex_lock(&st->mu);

    if (index >= st->chunks_cap) {
        size_t new_cap = st->chunks_cap ? st->chunks_cap * 2 : 16;
        while (new_cap <= index) new_cap *= 2;
        ChunkMeta *n = realloc(st->chunks, new_cap * sizeof(ChunkMeta));
        if (!n) {
            perror("realloc chunks");
        } else {
            st->chunks = n;
            st->chunks_cap = new_cap;
        }
    }

    if (index < st->chunks_cap) {
        ChunkMeta *cm = &st->chunks[index];
        cm->index = index;
        cm->size  = len;
        strncpy(cm->hash, hash_hex, sizeof(cm->hash));
        cm->hash[sizeof(cm->hash) - 1] = '\0';
    }

    st->pending_tasks--;
    pthread_cond_broadcast(&st->cv);
    pthread_mutex_unlock(&st->mu);

    free(data);  // chunk buffer owned by task
}

/* -------- download task processing -------- */

static void process_download_task(Task *t) {
    DownloadState *ds = t->u.download.st;
    uint32_t index    = t->u.download.index;
    char *hash_hex    = t->u.download.hash;

    char path[PATH_MAX];
    make_block_path(hash_hex, path);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open block");
        pthread_mutex_lock(&ds->mu);
        if (index < ds->n_chunks) {
            ds->slots[index].ready = 1;
            ds->slots[index].error = 1;
        }
        pthread_cond_broadcast(&ds->cv);
        pthread_mutex_unlock(&ds->mu);
        return;
    }

    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < 0) { perror("lseek"); close(fd); return; }
    if (lseek(fd, 0, SEEK_SET) < 0) { perror("lseek"); close(fd); return; }

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { perror("malloc block"); close(fd); return; }

    if (read_n(fd, buf, (size_t)sz) != sz) {
        perror("read block");
        free(buf);
        close(fd);
        return;
    }
    close(fd);

    // Verify hash
    char verify[65];
    blake3_hex(buf, (size_t)sz, verify);
    int err = (strcmp(verify, hash_hex) != 0);

    pthread_mutex_lock(&ds->mu);
    if (index < ds->n_chunks) {
        ds->slots[index].ready = 1;
        ds->slots[index].error = err;
        if (!err) {
            ds->slots[index].data = buf;
            ds->slots[index].size = (uint32_t)sz;
            buf = NULL; // ownership moved
        }
    }
    pthread_cond_broadcast(&ds->cv);
    pthread_mutex_unlock(&ds->mu);

    free(buf); // free only if not moved
}

/* -------- worker thread -------- */

static void* worker_main(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&q_mu);
        while (!q_head) {
            pthread_cond_wait(&q_cv, &q_mu);
        }
        Task *t = q_head;
        q_head = t->next;
        if (!q_head) q_tail = NULL;
        pthread_mutex_unlock(&q_mu);

        if (t->type == TASK_UPLOAD) {
            process_upload_task(t);
        } else if (t->type == TASK_DOWNLOAD) {
            process_download_task(t);
        }
        free(t);
    }
    return NULL;
}





