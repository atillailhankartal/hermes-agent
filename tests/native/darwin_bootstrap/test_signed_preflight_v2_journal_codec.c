#include "signed_preflight_v2_journal_codec.h"
#include <stdio.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    bh_journal_snapshot journal;
    bh_journal_snapshot selector;
    bh_journal_action action;
    int has_candidate;
    bh_journal_candidate candidate;
    bh_journal_outcome expected;
    const char *diagnosis;
    const char *external_reason;
    int off;
} journal_case;

#include "journal_vectors.h"

static unsigned int capacity_tests(void)
{
    unsigned int failures = 0;
    size_t i;
    const size_t seed_length = 282;
    const size_t count_length = seed_length * (BH_JOURNAL_MAX_RECORDS + 1);
    uint8_t *bytes = malloc(BH_JOURNAL_MAX_BYTES + 1);
    bh_journal_snapshot snapshot;
    bh_journal_observation got;
    int passed;
    if (bytes == NULL) {
        puts("FAIL Capacity_WhenAllocationFails_NoCoverage");
        return 2;
    }
    for (i = 0; i < BH_JOURNAL_MAX_RECORDS + 1; ++i) {
        memcpy(bytes + i * seed_length, cases[0].journal.bytes, seed_length);
    }
    snapshot.bytes = bytes;
    snapshot.length = count_length;
    snapshot.present = 1;
    got = bh_journal_observe(snapshot, cases[0].selector, &parameters,
                             BH_JOURNAL_STARTUP_RECOVER, NULL);
    passed = got.outcome == BH_JOURNAL_UNAVAILABLE && got.off == 1 &&
        strcmp(got.parser_diagnosis, "record_count") == 0 &&
        strcmp(got.external_reason, "persisted_state_unavailable") == 0 &&
        got.pid == 0 && got.journal_appends == 0 && got.selector_renames == 0;
    printf("%s Capacity_When4097Records_ReturnsUnavailable reason=%s\n",
           passed ? "PASS" : "FAIL", got.parser_diagnosis);
    failures += passed ? 0U : 1U;
    snapshot.length = BH_JOURNAL_MAX_BYTES + 1;
    got = bh_journal_observe(snapshot, cases[0].selector, &parameters,
                             BH_JOURNAL_STARTUP_RECOVER, NULL);
    passed = got.outcome == BH_JOURNAL_UNAVAILABLE && got.off == 1 &&
        strcmp(got.parser_diagnosis, "journal_size") == 0 &&
        strcmp(got.external_reason, "persisted_state_unavailable") == 0 &&
        got.pid == 0 && got.journal_appends == 0 && got.selector_renames == 0;
    printf("%s Capacity_WhenByteCapExceeded_ReturnsUnavailable reason=%s\n",
           passed ? "PASS" : "FAIL", got.parser_diagnosis);
    failures += passed ? 0U : 1U;
    free(bytes);
    return failures;
}

/* Independent candidate fixture bytes: never copied from persisted ACTIVE. */
static bh_journal_candidate boundary_candidate(int armed, uint64_t epoch)
{
    static const uint8_t policy[] = "test-policy-old-v6";
    static const uint8_t manifest[] = "test-manifest-old-v6";
    bh_journal_candidate c = {{0}, 0, 0, {0}, {0}, {0}, {0}, 0};
    memset(c.installation_id, 0x10, 32);
    c.epoch = epoch;
    c.key_state = armed ? 2 : 1;
    (void)CC_SHA256(policy, (CC_LONG)(sizeof(policy) - 1), c.policy_digest);
    (void)CC_SHA256(manifest, (CC_LONG)(sizeof(manifest) - 1), c.manifest_digest);
    if (armed) { memset(c.new_key_id, 0xa5, 32); }
    memcpy(c.version_id, armed ? "upper-v1" : "old-v6", armed ? 8U : 6U);
    c.version_length = armed ? 8U : 6U;
    return c;
}

static unsigned int boundary_tests(void)
{
    static const char *names[] = {
        "ThresholdMax_Startup_Unavailable",
        "ThresholdMax_SameEpoch_Unavailable",
        "ThresholdMax_Advance_Unavailable",
        "ThresholdMaxMinusOne_ArmedAdvance_PrecheckOnly"
    };
    size_t i;
    unsigned int failures = 0;
    for (i = 0; i < 4; ++i) {
        bh_journal_parameters p = parameters;
        bh_journal_candidate c;
        bh_journal_action action = i == 0 ? BH_JOURNAL_STARTUP_RECOVER :
            (i == 1 ? BH_JOURNAL_SAME_EPOCH_CANDIDATE : BH_JOURNAL_ADVANCE_CANDIDATE);
        bh_journal_outcome expected = i == 3 ? BH_JOURNAL_CANDIDATE_ELIGIBLE_ONLY : BH_JOURNAL_UNAVAILABLE;
        const char *diagnosis = i == 3 ? "exact_active_selector" : "parameters_invalid";
        const char *reason = i == 3 ? "candidate_precheck_only" : "persisted_state_unavailable";
        int off = i == 3 ? 0 : 1;
        bh_journal_observation got;
        int passed;
        p.threshold_t = i == 3 ? UINT64_MAX - 1 : UINT64_MAX;
        c = boundary_candidate(i >= 2, i >= 2 ? p.threshold_t : 6);
        got = bh_journal_observe(cases[0].journal, cases[0].selector, &p,
                                action, i == 0 ? NULL : &c);
        passed = got.outcome == expected && got.parser_diagnosis != NULL &&
            strcmp(got.parser_diagnosis, diagnosis) == 0 && got.external_reason != NULL &&
            strcmp(got.external_reason, reason) == 0 && got.off == off &&
            got.pid == 0 && got.journal_appends == 0 && got.selector_renames == 0;
        printf("%s Boundary_When_%s expected=%d/%s/%s/off=%d actual=%d/%s/%s/off=%d pid=%u appends=%u renames=%u\n",
            passed ? "PASS" : "FAIL", names[i], (int)expected, diagnosis, reason, off,
            (int)got.outcome, got.parser_diagnosis != NULL ? got.parser_diagnosis : "NULL",
            got.external_reason != NULL ? got.external_reason : "NULL", got.off,
            got.pid, got.journal_appends, got.selector_renames);
        failures += passed ? 0U : 1U;
    }
    return failures;
}

int main(void)
{
    size_t i;
    unsigned int failures = 0U;
    const size_t count = sizeof(cases) / sizeof(cases[0]);
    if (count != 54U) {
        fprintf(stderr, "FAIL Registry_WhenLiteralCorpusChanges_Rejects count=%zu\n", count);
        return 2;
    }
    for (i = 0U; i < count; ++i) {
        const journal_case *test = &cases[i];
        bh_journal_observation got = bh_journal_observe(test->journal,
            test->selector, &parameters, test->action,
            test->has_candidate ? &test->candidate : NULL);
        int passed = got.outcome == test->expected &&
            got.parser_diagnosis != NULL &&
            strcmp(got.parser_diagnosis, test->diagnosis) == 0 &&
            got.external_reason != NULL &&
            strcmp(got.external_reason, test->external_reason) == 0 &&
            got.off == test->off &&
            got.pid == 0U && got.journal_appends == 0U &&
            got.selector_renames == 0U;
        printf("%s Codec_When_%s expected=%d/%s/reason=%s/off=%d actual=%d/%s/reason=%s/off=%d pid=%u appends=%u renames=%u\n",
            passed ? "PASS" : "FAIL", test->name, (int)test->expected,
            test->diagnosis, test->external_reason, test->off, (int)got.outcome,
            got.parser_diagnosis != NULL ? got.parser_diagnosis : "NULL",
            got.external_reason != NULL ? got.external_reason : "NULL", got.off,
            got.pid, got.journal_appends, got.selector_renames);
        if (!passed) { ++failures; }
    }
    failures += capacity_tests();
    failures += boundary_tests();
    printf("REGISTRY boundary=4 capacity=2 cases=%zu executed=%zu failures=%u skips=0\n", count, count, failures);
    return failures == 0U ? 0 : 1;
}
