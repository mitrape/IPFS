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
#define OP_ERROR 0xFF
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

/* send error*/
static void send_error(int fd, const char *code, const char *msg) {
    char buf[256];
    int n = snprintf(buf,sizeof(buf),
            "{\"code\":\"%s\",\"message\":\"%s\"}", code, msg);
    send_frame(fd, OP_ERROR, buf, n);
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
// مسیر فایل refcount برای هر بلاک: ipfs_store/blocks/aa/bb/<hash>.ref
static void make_refcount_path(const char *hash_hex, char out[PATH_MAX]) {
    char d1[3] = { hash_hex[0], hash_hex[1], '\0' };
    char d2[3] = { hash_hex[2], hash_hex[3], '\0' };
    snprintf(out, PATH_MAX, "%s/%s/%s/%s.ref", BLOCKS_DIR, d1, d2, hash_hex);
}

// افزایش refcount برای بلاک با این hash
static void inc_refcount(const char *hash_hex) {
    char refpath[PATH_MAX];
    make_refcount_path(hash_hex, refpath);

    // اگر دایرکتوری‌ها هنوز ساخته نشده‌اند، بساز
    if (ensure_parents_for_path(refpath) < 0) {
        fprintf(stderr, "inc_refcount: ensure_parents_for_path failed\n");
        return;
    }

    int cnt = 0;
    FILE *f = fopen(refpath, "r");
    if (f) {
        if (fscanf(f, "%d", &cnt) != 1) {
            // اگر چیزی نخوند، فرض می‌کنیم صفر بود
            cnt = 0;
        }
        fclose(f);
    }

    f = fopen(refpath, "w");
    if (!f) {
        perror("fopen refcount");
        return;
    }
    fprintf(f, "%d\n", cnt + 1);
    fclose(f);
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

    // چک کن بلاک از قبل وجود دارد یا نه
    
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        // already exists
        existed = 1;
        close(fd);
    } else {
        // اگر وجود نداشت، فایل بلاک را اتمیک بنویس
        if (write_file_atomic(path, data, len) < 0) {
            fprintf(stderr, "Failed to write block %s\n", path);
            // حتی اگر نوشتن بلاک fail شود، هنوز هم می‌توانیم manifest بسازیم،
            // ولی در عمل بهتر است بعداً این را به ERROR تبدیل کنیم.
        }
    }

    // در هر دو حالت، refcount را زیاد کن
    inc_refcount(hash_hex);

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
            ds->slots[index].error = 1;  // 1 = "chunk not found or I/O error"
        }
        pthread_cond_broadcast(&ds->cv);
        pthread_mutex_unlock(&ds->mu);
        return;
    }

    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < 0) {
        perror("lseek");
        close(fd);
        pthread_mutex_lock(&ds->mu);
        if (index < ds->n_chunks) {
            ds->slots[index].ready = 1;
            ds->slots[index].error = 1;
        }
        pthread_cond_broadcast(&ds->cv);
        pthread_mutex_unlock(&ds->mu);
        return;
    }
    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek");
        close(fd);
        pthread_mutex_lock(&ds->mu);
        if (index < ds->n_chunks) {
            ds->slots[index].ready = 1;
            ds->slots[index].error = 1;
        }
        pthread_cond_broadcast(&ds->cv);
        pthread_mutex_unlock(&ds->mu);
        return;
    }

    uint8_t *buf = malloc((size_t)sz);
    if (!buf) {
        perror("malloc block");
        close(fd);
        pthread_mutex_lock(&ds->mu);
        if (index < ds->n_chunks) {
            ds->slots[index].ready = 1;
            ds->slots[index].error = 1;
        }
        pthread_cond_broadcast(&ds->cv);
        pthread_mutex_unlock(&ds->mu);
        return;
    }

    if (read_n(fd, buf, (size_t)sz) != sz) {
        perror("read block");
        free(buf);
        close(fd);
        pthread_mutex_lock(&ds->mu);
        if (index < ds->n_chunks) {
            ds->slots[index].ready = 1;
            ds->slots[index].error = 1;
        }
        pthread_cond_broadcast(&ds->cv);
        pthread_mutex_unlock(&ds->mu);
        return;
    }
    close(fd);

    // Verify hash
    char verify[65];
    blake3_hex(buf, (size_t)sz, verify);
    int mismatch = (strcmp(verify, hash_hex) != 0);

    pthread_mutex_lock(&ds->mu);
    if (index < ds->n_chunks) {
        ds->slots[index].ready = 1;
        if (mismatch) {
            ds->slots[index].error = 2;  // 2 = HASH_MISMATCH
        } else {
            ds->slots[index].error = 0;
            ds->slots[index].data  = buf;
            ds->slots[index].size  = (uint32_t)sz;
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
/* ==================== Manifest building/parsing ==================== */

static int build_manifest_json(const UploadState *st,
                               char **out_buf, size_t *out_len,
                               char cid_hex_out[65]) {
    char *buf = NULL;
    size_t len = 0;

    FILE *mf = open_memstream(&buf, &len);
    if (!mf) {
        perror("open_memstream");
        return -1;
    }

    pthread_mutex_lock((pthread_mutex_t *)&st->mu); // const-cast for read
    uint32_t total_chunks = st->total_chunks;
    uint64_t total_size   = st->total_size;

    fprintf(mf, "{\"version\":1");
    fprintf(mf, ",\"hash_algo\":\"blake3\"");
    fprintf(mf, ",\"chunk_size\":%u", (unsigned)DEFAULT_CHUNK_SIZE);
    fprintf(mf, ",\"total_size\":%" PRIu64, total_size);
    fprintf(mf, ",\"filename\":\"%s\"", st->filename ? st->filename : "");
    fprintf(mf, ",\"chunks\":[");

    for (uint32_t i = 0; i < total_chunks; i++) {
        const ChunkMeta *cm = &st->chunks[i];
        fprintf(mf,
                "{\"index\":%u,\"size\":%u,\"hash\":\"%s\"}%s",
                cm->index, cm->size, cm->hash,
                (i + 1 < total_chunks) ? "," : "");
    }
    fprintf(mf, "]}");
    pthread_mutex_unlock((pthread_mutex_t *)&st->mu);

    fflush(mf);
    fclose(mf);

    blake3_hex((const uint8_t*)buf, len, cid_hex_out);

    *out_buf = buf;
    *out_len = len;
    return 0;
}

typedef struct {
    size_t n_chunks;
    ChunkMeta *chunks;   // only hash+index used
} ManifestChunks;

static void manifest_chunks_free(ManifestChunks *m) {
    if (!m) return;
    free(m->chunks);
    m->chunks = NULL;
    m->n_chunks = 0;
}

// Very shallow parser for our own manifest format
static int load_manifest_chunks(const char *cid, ManifestChunks *out) {
    char path[PATH_MAX];
    make_manifest_path(cid, path);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open manifest");
        return -1;
    }

    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) { perror("lseek"); close(fd); return -1; }
    if (lseek(fd, 0, SEEK_SET) < 0) { perror("lseek"); close(fd); return -1; }

    char *buf = malloc((size_t)size + 1);
    if (!buf) { perror("malloc manifest"); close(fd); return -1; }

    if (read_n(fd, buf, (size_t)size) != size) {
        perror("read manifest");
        close(fd);
        free(buf);
        return -1;
    }
    close(fd);
    buf[size] = '\0';

    const char *needle = "\"hash\":\"";
    char *p = buf;
    ChunkMeta *chunks = NULL;
    size_t cap = 0, len_chunks = 0;

    while ((p = strstr(p, needle)) != NULL) {
        p += strlen(needle);
        char *end = strchr(p, '\"');
        if (!end) break;
        size_t hlen = (size_t)(end - p);
        if (hlen >= 64) hlen = 64;

        if (len_chunks == cap) {
            size_t new_cap = cap ? cap * 2 : 16;
            ChunkMeta *n = realloc(chunks, new_cap * sizeof(ChunkMeta));
            if (!n) {
                perror("realloc manifest chunks");
                free(chunks);
                free(buf);
                return -1;
            }
            chunks = n;
            cap = new_cap;
        }

        ChunkMeta *cm = &chunks[len_chunks];
        cm->index = (uint32_t)len_chunks;
        cm->size  = 0;
        memset(cm->hash, 0, sizeof(cm->hash));
        memcpy(cm->hash, p, hlen);
        cm->hash[hlen] = '\0';

        len_chunks++;
        p = end + 1;
    }

    free(buf);

    out->n_chunks = len_chunks;
    out->chunks   = chunks;
    return 0;
}

/* ==================== Connection handler ==================== */

static int queue_upload_chunk(UploadState *st, uint8_t *data, uint32_t len) {
    Task *t = (Task*)calloc(1, sizeof(Task));
    if (!t) {
        perror("calloc task");
        return -1;
    }
    t->type = TASK_UPLOAD;
    t->u.upload.st   = st;
    t->u.upload.data = data;
    t->u.upload.size = len;

    pthread_mutex_lock(&st->mu);
    uint32_t index = st->next_index++;
    st->total_chunks = st->next_index;
    st->total_size  += len;
    st->pending_tasks++;
    pthread_mutex_unlock(&st->mu);

    t->u.upload.index = index;

    enqueue_task(t);
    return 0;
}

static void handle_connection(int cfd) {
    UploadState up;
    upload_state_construct(&up);

    for (;;) {
        uint8_t header[5];
        ssize_t r = read_n(cfd, header, 5);
        if (r == 0) break;
        if (r < 0) break;

        uint8_t op = header[0];
        uint32_t len;
        memcpy(&len, header + 1, 4);
        len = ntohl(len);

        uint8_t *payload = NULL;
        if (len) {
            payload = (uint8_t*)malloc(len);
            if (!payload) { perror("malloc"); break; }
            if (read_n(cfd, payload, len) <= 0) {
                free(payload);
                break;
            }
        }

        int free_payload = 1;

        if (op == OP_UPLOAD_START) {
            printf("[ENGINE] UPLOAD_START: name=\"%.*s\"\n",
                   (int)len, (char*)payload);
            fflush(stdout);

            upload_state_reset(&up);
            pthread_mutex_lock(&up.mu);
            up.active = 1;
            up.filename = (char*)malloc(len + 1);
            if (!up.filename) {
                perror("malloc filename");
                pthread_mutex_unlock(&up.mu);
                free(payload);
                break;
            }
            memcpy(up.filename, payload, len);
            up.filename[len] = '\0';
            pthread_mutex_unlock(&up.mu);

        } else if (op == OP_UPLOAD_CHUNK) {
    if (!up.active) {
        fprintf(stderr, "UPLOAD_CHUNK بدون UPLOAD_START\n");
        send_error(cfd, "E_PROTO", "UPLOAD_CHUNK before UPLOAD_START");
    } else {
        if (queue_upload_chunk(&up, payload, len) < 0) {
            fprintf(stderr, "Failed to queue upload chunk\n");
            send_error(cfd, "E_BUSY", "cannot queue upload chunk");
            free(payload);
            break;
        }
        free_payload = 0; // task owns payload
    }

        } else if (op == OP_UPLOAD_FINISH) {
    printf("[ENGINE] UPLOAD_FINISH\n");
    fflush(stdout);

    // صبر کن تا همه‌ی تسک‌های آپلود تموم بشن
    pthread_mutex_lock(&up.mu);
    while (up.pending_tasks > 0) {
        pthread_cond_wait(&up.cv, &up.mu);
    }
    up.active = 0;
    pthread_mutex_unlock(&up.mu);

    // ✅ کد جدید: چک کن هیچ چانکی جا نیفتاده
    int missing = 0;
    pthread_mutex_lock(&up.mu);
    for (uint32_t i = 0; i < up.total_chunks; i++) {
        // اگر ظرفیت آرایه به هر دلیل کمتر باشه، یا size صفر باشه → مشکل
        if (i >= up.chunks_cap || up.chunks[i].size == 0) {
            missing = 1;
            break;
        }
    }
    pthread_mutex_unlock(&up.mu);

    if (missing) {
        fprintf(stderr, "UPLOAD_FINISH: missing chunk(s)\n");
        send_error(cfd, "E_PROTO", "missing chunk in upload");
        upload_state_reset(&up);
        // اتصال رو می‌بندیم، از حلقه‌ی اصلی میایم بیرون
        break;
    }

    // از اینجا به بعد مثل قبل
    char *manifest = NULL;
    size_t manifest_len = 0;
    char cid[65];

    if (build_manifest_json(&up, &manifest, &manifest_len, cid) < 0) {
        fprintf(stderr, "Failed to build manifest\n");
        send_error(cfd, "E_BUSY", "failed to build manifest");
        free(payload);
        break;
    }

    char manifest_path[PATH_MAX];
    make_manifest_path(cid, manifest_path);

    if (write_file_atomic(manifest_path, manifest, manifest_len) < 0) {
        fprintf(stderr, "Failed to write manifest %s\n", manifest_path);
        send_error(cfd, "E_BUSY", "failed to write manifest");
        free(manifest);
        free(payload);
        break;
    }
    free(manifest);

    printf("[ENGINE] UPLOAD_FINISH -> CID %s\n", cid);
    fflush(stdout);

    send_frame(cfd, OP_UPLOAD_DONE, cid, (uint32_t)strlen(cid));

    upload_state_reset(&up);

        } else if (op == OP_DOWNLOAD_START) {
            char *cid = (char*)malloc(len + 1);
            if (!cid) {
                perror("malloc cid");
                free(payload);
                break;
            }
            memcpy(cid, payload, len);
            cid[len] = '\0';

            printf("[ENGINE] DOWNLOAD_START: cid=\"%s\"\n", cid);
            fflush(stdout);

            ManifestChunks m;
            m.n_chunks = 0;
            m.chunks   = NULL;

            if (load_manifest_chunks(cid, &m) < 0 || m.n_chunks == 0) {
                fprintf(stderr, "Failed to load manifest for cid %s\n", cid);
                send_error(cfd, "E_NOT_FOUND", "manifest not found");
                free(cid);
                free(payload);
                break;
            }

            DownloadState ds;
            download_state_construct(&ds, m.n_chunks);

            // create tasks for each chunk
            for (size_t i = 0; i < m.n_chunks; i++) {
                Task *t = (Task*)calloc(1, sizeof(Task));
                if (!t) {
                    perror("calloc download task");
                    continue;
                }
                t->type = TASK_DOWNLOAD;
                t->u.download.st    = &ds;
                t->u.download.index = (uint32_t)i;
                strncpy(t->u.download.hash, m.chunks[i].hash,
                        sizeof(t->u.download.hash));
                t->u.download.hash[sizeof(t->u.download.hash) - 1] = '\0';

                enqueue_task(t);
               
            }

            int any_error = 0;

// sequential merger: wait index by index
for (size_t i = 0; i < m.n_chunks; i++) {
    pthread_mutex_lock(&ds.mu);
    while (!ds.slots[i].ready) {
        pthread_cond_wait(&ds.cv, &ds.mu);
    }
    int err_code    = ds.slots[i].error;
    uint8_t *data   = ds.slots[i].data;
    uint32_t sz     = ds.slots[i].size;
    pthread_mutex_unlock(&ds.mu);

    if (err_code != 0 || !data) {
        any_error = 1;
        if (err_code == 1) {
            send_error(cfd, "E_NOT_FOUND", "chunk not found");
        } else if (err_code == 2) {
            send_error(cfd, "E_HASH_MISMATCH", "chunk hash mismatch");
        } else {
            send_error(cfd, "E_BUSY", "download chunk failed");
        }
        fprintf(stderr,
                "Error in download chunk %zu for cid %s (err=%d)\n",
                i, cid, err_code);
        break;
    }

    if (send_frame(cfd, OP_DOWNLOAD_CHUNK, data, sz) < 0) {
        fprintf(stderr, "send_frame DOWNLOAD_CHUNK failed\n");
        any_error = 1;
        send_error(cfd, "E_BUSY", "send DOWNLOAD_CHUNK failed");
        break;
    }

    free(data);
    ds.slots[i].data = NULL;
}

if (!any_error) {
    send_frame(cfd, OP_DOWNLOAD_DONE, NULL, 0);
}
            

            download_state_destroy(&ds);
            manifest_chunks_free(&m);
            free(cid);

        } else {
            fprintf(stderr, "Unknown opcode: 0x%02x\n", op);
            send_error(cfd, "E_PROTO", "unknown opcode");
        }

        if (free_payload && payload) free(payload);
    }

    upload_state_destroy(&up);
    close(cfd);
}

/* ==================== main ==================== */

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s /tmp/cengine.sock\n", argv[0]);
        return 2;
    }
    g_sock_path = argv[1];

    if (ensure_dir(STORAGE_ROOT) < 0) return 1;
    if (ensure_dir(BLOCKS_DIR) < 0) return 1;
    if (ensure_dir(MANIFESTS_DIR) < 0) return 1;

    // start global thread pool
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_t th;
        pthread_create(&th, NULL, worker_main, NULL);
        pthread_detach(th);
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) die("socket");

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_sock_path, sizeof(addr.sun_path) - 1);

    unlink(g_sock_path);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) die("bind");
    if (listen(fd, 64) < 0) die("listen");

    printf("[ENGINE] listening on %s\n", g_sock_path);
    fflush(stdout);

    for (;;) {
        int cfd = accept(fd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        pthread_t th;
        pthread_create(&th, NULL, (void*(*)(void*))handle_connection,
                       (void*)(intptr_t)cfd);
        pthread_detach(th);
    }

    close(fd);
    unlink(g_sock_path);
    return 0;
}




