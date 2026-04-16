// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions: tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <n>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "index.h"
// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE 0100644
#define MODE_EXEC 0100755
#define MODE_DIR  0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISDIR(st.st_mode)) return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1;

        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);
        ptr = space + 1;

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1;

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0';
        ptr = null_byte + 1;

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1;
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }

    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    size_t max_size = tree->count * 296;
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];

        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 for the null terminator

        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── IMPLEMENTED ─────────────────────────────────────────────────────────────

// Forward declarations
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// Helper: write one level of the tree.
// entries[] is an array of index entries whose paths (relative to `prefix`)
// all live at depth `depth` or deeper.
// Returns 0 on success, -1 on error.
static int write_tree_level(IndexEntry *entries, int count, const char *prefix,
                            ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    int i = 0;
    while (i < count) {
        const char *rel = entries[i].path;
        // Advance past the prefix
        if (prefix[0] != '\0') {
            size_t plen = strlen(prefix);
            if (strncmp(rel, prefix, plen) == 0 && rel[plen] == '/')
                rel = rel + plen + 1;
        }

        // Is there a slash in the remaining path? → subdirectory
        const char *slash = strchr(rel, '/');
        if (slash) {
            // This entry belongs to a subdirectory
            // Extract the subdirectory name
            size_t dir_len = slash - rel;
            char dir_name[256];
            if (dir_len >= sizeof(dir_name)) return -1;
            strncpy(dir_name, rel, dir_len);
            dir_name[dir_len] = '\0';

            // Collect all entries that belong to this subdirectory
            // Build the full prefix for this subdirectory
            char sub_prefix[512];
            if (prefix[0] != '\0')
                snprintf(sub_prefix, sizeof(sub_prefix), "%s/%s", prefix, dir_name);
            else
                snprintf(sub_prefix, sizeof(sub_prefix), "%s", dir_name);

            // Find all entries with this prefix
            int j = i;
            while (j < count) {
                const char *p = entries[j].path;
                size_t splen = strlen(sub_prefix);
                if (strncmp(p, sub_prefix, splen) == 0 &&
                    (p[splen] == '/' || p[splen] == '\0')) {
                    j++;
                } else {
                    break;
                }
            }

            // Recursively write this subdirectory's tree
            ObjectID sub_id;
            if (write_tree_level(entries + i, j - i, sub_prefix, &sub_id) != 0)
                return -1;

            // Add entry for this directory
            TreeEntry *te = &tree.entries[tree.count];
            te->mode = MODE_DIR;
            strncpy(te->name, dir_name, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            te->hash = sub_id;
            tree.count++;

            i = j;
        } else {
            // This is a plain file at this level
            TreeEntry *te = &tree.entries[tree.count];
            te->mode = entries[i].mode;
            strncpy(te->name, rel, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            te->hash = entries[i].hash;
            tree.count++;
            i++;
        }

        if (tree.count >= MAX_TREE_ENTRIES) break;
    }

    // Serialize and write the tree
    void *tree_data;
    size_t tree_len;
    if (tree_serialize(&tree, &tree_data, &tree_len) != 0) return -1;

    int rc = object_write(OBJ_TREE, tree_data, tree_len, id_out);
    free(tree_data);
    return rc;
}

// Sort helper for index entries by path
static int compare_index_entries(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path, ((const IndexEntry *)b)->path);
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
// Returns 0 on success, -1 on error.
int tree_from_index(ObjectID *id_out) {
    Index index;
    index.count = 0;

    if (index_load(&index) != 0) return -1;
    if (index.count == 0) {
        // Empty tree: write an empty tree object
        Tree empty;
        empty.count = 0;
        void *tree_data;
        size_t tree_len;
        if (tree_serialize(&empty, &tree_data, &tree_len) != 0) return -1;
        int rc = object_write(OBJ_TREE, tree_data, tree_len, id_out);
        free(tree_data);
        return rc;
    }

    // Sort entries by path for consistent tree building
    qsort(index.entries, index.count, sizeof(IndexEntry), compare_index_entries);

    return write_tree_level(index.entries, index.count, "", id_out);
}
