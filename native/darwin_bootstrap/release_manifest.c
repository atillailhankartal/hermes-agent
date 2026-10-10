#include "abi_v1.h"

#include <string.h>

static int fixed_path(const char *path, size_t capacity) {
    size_t length = strnlen(path, capacity);
    size_t component_start = 1;
    size_t index;
    if (length < 2 || length == capacity || path[0] != '/' ||
        path[length - 1] == '/') return 0;
    for (index = 1; index <= length; index++) {
        if (path[index] != '/' && path[index] != '\0') continue;
        if (index == component_start ||
            (index - component_start == 1 && path[component_start] == '.') ||
            (index - component_start == 2 && path[component_start] == '.' &&
             path[component_start + 1] == '.')) return 0;
        component_start = index + 1;
    }
    return 1;
}

enum bh_a2a_result bh_a2a_manifest_validate(const struct bh_a2a_manifest_v1 *manifest) {
    size_t leaf_length;
    unsigned int digest_nonzero = 0;
    size_t index;
    if (manifest == NULL || manifest->version != 1 ||
        !fixed_path(manifest->parent_path, sizeof(manifest->parent_path)) ||
        !fixed_path(manifest->stage0_path, sizeof(manifest->stage0_path)))
        return BH_A2A_PAUSED;
    leaf_length = strnlen(manifest->leaf, sizeof(manifest->leaf));
    if (leaf_length == 0 || leaf_length == sizeof(manifest->leaf) ||
        (leaf_length == 1 && manifest->leaf[0] == '.') ||
        (leaf_length == 2 && manifest->leaf[0] == '.' && manifest->leaf[1] == '.') ||
        strchr(manifest->leaf, '/') != NULL || manifest->broker_uid == 0 ||
        manifest->parent_device == 0 || manifest->parent_inode == 0)
        return BH_A2A_PAUSED;
    for (index = 0; index < sizeof(manifest->release_digest); index++)
        digest_nonzero |= manifest->release_digest[index];
    return digest_nonzero != 0 ? BH_A2A_OK : BH_A2A_PAUSED;
}
