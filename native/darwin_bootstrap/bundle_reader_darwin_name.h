#ifndef BH_BUNDLE_READER_DARWIN_NAME_H
#define BH_BUNDLE_READER_DARWIN_NAME_H
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/attr.h>
#include <unistd.h>
/* getattrlist(2): NAME is an attrreference_t with an offset relative to itself.
 * RETURNED_ATTRS qualifies support. Bounds include silent truncation and signed
 * offsets. A case-insensitive lookup must still name the exact frozen entry. */
static int bh_br_darwin_exact_name(int dir, const char *name) {
    struct attrlist request = {0};
    struct {
        uint32_t length;
        attribute_set_t returned;
        attrreference_t name;
        unsigned char storage[1024];
    } value = {0};
    request.bitmapcount = ATTR_BIT_MAP_COUNT;
    request.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME;
    if (getattrlistat(dir, name, &request, &value, sizeof(value), FSOPT_NOFOLLOW)) return -1;
    size_t base = (size_t)((unsigned char *)&value.name - (unsigned char *)&value);
    if (value.length < base + sizeof(value.name) || value.length > sizeof(value) ||
        !(value.returned.commonattr & ATTR_CMN_NAME) || value.name.attr_dataoffset < (int32_t)sizeof(value.name)) {
        errno = EIO; return -1;
    }
    size_t start = base + (uint32_t)value.name.attr_dataoffset;
    size_t count = value.name.attr_length;
    if (start > value.length || count > value.length - start || count == 0) {
        errno = EIO; return -1;
    }
    if (count != strlen(name) + 1 || memcmp((unsigned char *)&value + start, name, count)) {
        errno = ENOENT; return -1;
    }
    return 0;
}
#endif
