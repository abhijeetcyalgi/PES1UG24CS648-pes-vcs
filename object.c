// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────
    int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Step 1: Build header
    char header[64];
    const char *type_str =
        (type == OBJ_BLOB) ? "blob" :
        (type == OBJ_TREE) ? "tree" :
        "commit";

    int header_len = sprintf(header, "%s %zu", type_str, len);
    header[header_len] = '\0';
    header_len += 1; // include null byte

    // Step 2: Combine header + data
    size_t full_len = header_len + len;
    unsigned char *full = malloc(full_len);
    if (!full) return -1;

    memcpy(full, header, header_len);
    memcpy(full + header_len, data, len);

    // Step 3: Compute hash
    ObjectID hash;
    compute_hash(full, full_len, &hash);

    // Step 4: Check if exists
    if (object_exists(&hash)) {
        if (id_out) *id_out = hash;
        free(full);
        return 0;
    }

    // Step 5: Get path
    char path[256];
    object_path(&hash, path, sizeof(path));

    // Step 6: Create directory (.pes/objects/xx)
    char dir[256];
    strcpy(dir, path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir, 0755);
    }

    // Step 7: Write to temp file
    char temp_path[300];
    sprintf(temp_path, "%s.tmp", path);

    int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full);
        return -1;
    }

    if (write(fd, full, full_len) < 0) {
        close(fd);
        free(full);
        return -1;
    }

    fsync(fd);
    close(fd);

    // Step 8: Rename
    rename(temp_path, path);

    // Step 9: Output hash
    if (id_out) *id_out = hash;

    free(full);
    return 0;
}

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Step 1: Get path
    char path[256];
    object_path(id, path, sizeof(path));

    // Step 2: Open file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // Step 3: Read file
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    fread(buf, 1, size, f);
    fclose(f);

    // Step 4: Verify hash
    ObjectID check;
    compute_hash(buf, size, &check);

    if (memcmp(&check, id, sizeof(ObjectID)) != 0) {
        free(buf);
        return -1;
    }

    // Step 5: Parse header
    char *null_pos = memchr(buf, '\0', size);
    if (!null_pos) {
        free(buf);
        return -1;
    }

    char *header = (char *)buf;
    size_t header_len = null_pos - header + 1;

    char type_str[10];
    size_t data_size;

    sscanf(header, "%s %zu", type_str, &data_size);

    // Step 6: Set type
    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else *type_out = OBJ_COMMIT;

    // Step 7: Extract data
    *data_out = malloc(data_size);
    memcpy(*data_out, buf + header_len, data_size);

    *len_out = data_size;

    // Step 8: Cleanup
    free(buf);
    return 0;
}
