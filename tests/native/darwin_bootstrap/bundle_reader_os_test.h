#ifndef BH_BUNDLE_READER_OS_TEST_H
#define BH_BUNDLE_READER_OS_TEST_H
#include <sys/stat.h>
struct br_test_state {
    int scenario, variant, calls, opens, closes, owned, allocs, frees, live;
    int reads, acl_gets, acl_live, acl_frees, flags[3], fds[4], read_counts[3];
    int writer[3], borrowed, ambiguous, mutation, failure;
    struct stat original[3];
};
extern struct br_test_state br_test;
void br_test_reset(int scenario, int variant, int fd, const int writers[3]);
#endif
