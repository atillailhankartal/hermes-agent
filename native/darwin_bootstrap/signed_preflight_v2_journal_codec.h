#ifndef BH_SIGNED_PREFLIGHT_V2_JOURNAL_CODEC_H
#define BH_SIGNED_PREFLIGHT_V2_JOURNAL_CODEC_H

#include <stddef.h>
#include <stdint.h>

#define BH_JOURNAL_MAX_BYTES ((size_t)1392640)
#define BH_JOURNAL_MAX_RECORDS ((size_t)4096)
#define BH_SELECTOR_MAX_BYTES ((size_t)300)

typedef enum {
    BH_JOURNAL_UNAVAILABLE = 0,
    BH_JOURNAL_CONSISTENT_ONLY,
    BH_JOURNAL_OFF_PENDING,
    BH_JOURNAL_OFF_REJECT,
    BH_JOURNAL_CANDIDATE_ELIGIBLE_ONLY
} bh_journal_outcome;

typedef enum {
    BH_JOURNAL_STARTUP_RECOVER = 0,
    BH_JOURNAL_SAME_EPOCH_CANDIDATE,
    BH_JOURNAL_ADVANCE_CANDIDATE
} bh_journal_action;

/* Caller owns immutable bytes for the duration of the call. Missing and present
 * zero-length snapshots differ. No paths, FDs or ambient state are accepted. */
typedef struct {
    const uint8_t *bytes;
    size_t length;
    int present;
} bh_journal_snapshot;

typedef struct {
    uint8_t installation_id[32];
    uint64_t epoch;
    uint8_t key_state;
    uint8_t policy_digest[32];
    uint8_t manifest_digest[32];
    uint8_t new_key_id[32];
    uint8_t version_id[64];
    size_t version_length;
} bh_journal_candidate;

typedef struct {
    uint8_t installation_id[32];
    uint8_t new_key_id[32];
    uint64_t threshold_t;
} bh_journal_parameters;

typedef struct {
    bh_journal_outcome outcome;
    const char *parser_diagnosis;
    const char *external_reason;
    int off;
    unsigned int pid;
    unsigned int journal_appends;
    unsigned int selector_renames;
} bh_journal_observation;

/* Pure local format/consistency/precheck observations only. Candidate provenance
 * is untrusted here: no signed-policy, writer-exclusion, durability, rollback,
 * admission or launch authority is established. No persistence is performed.
 * candidate is independent of persisted ACTIVE and required for candidate actions.
 * All outcomes have PID0 and zero append/rename counts. */
bh_journal_observation bh_journal_observe(
    bh_journal_snapshot journal, bh_journal_snapshot selector,
    const bh_journal_parameters *parameters, bh_journal_action action,
    const bh_journal_candidate *candidate);

#endif
