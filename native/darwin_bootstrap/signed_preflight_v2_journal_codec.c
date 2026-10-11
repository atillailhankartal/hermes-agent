#include "signed_preflight_v2_journal_codec.h"
#include <CommonCrypto/CommonDigest.h>
#include <string.h>

/* Only bounded stack storage and caller-owned immutable snapshots. */
typedef struct {
    bh_journal_candidate tuple;
    const uint8_t *tx;
    const uint8_t *intent;
    const uint8_t *digest;
    const uint8_t *previous;
    uint64_t sequence;
    uint8_t type;
    size_t length;
} record;

static int zero(const uint8_t *p, size_t n)
{
    uint8_t bits = 0;
    size_t i;
    for (i = 0; i < n; ++i) { bits |= p[i]; }
    return bits == 0;
}

static uint64_t be(const uint8_t *p, size_t n)
{
    uint64_t value = 0;
    size_t i;
    for (i = 0; i < n; ++i) { value = (value << 8) | p[i]; }
    return value;
}

static int alnum_id(uint8_t c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

static int version_valid(const uint8_t *p, size_t n)
{
    size_t i;
    if (n == 0 || n > 64 || !alnum_id(p[0]) || !alnum_id(p[n - 1])) { return 0; }
    for (i = 0; i < n; ++i) {
        if (!alnum_id(p[i]) && p[i] != '_' && p[i] != '-') { return 0; }
    }
    return 1;
}

static int digest_valid(const uint8_t *p, size_t n, int selector)
{
    static const uint8_t journal_domain[] = "BeeHermes.FloorJournal.v2";
    static const uint8_t selector_domain[] = "BeeHermes.FloorSelector.v2";
    uint8_t preimage[sizeof(selector_domain) + 340];
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    const uint8_t *domain = selector ? selector_domain : journal_domain;
    size_t domain_length = selector ? sizeof(selector_domain) : sizeof(journal_domain);
    /* Includes exactly the string's terminating NUL; never the stored digest. */
    if (n < 32 || n > 340) { return 0; }
    memcpy(preimage, domain, domain_length);
    memcpy(preimage + domain_length, p, n - 32);
    if (CC_SHA256(preimage, (CC_LONG)(domain_length + n - 32), digest) == NULL) { return 0; }
    return memcmp(digest, p + n - 32, 32) == 0;
}

static const char *parse(const uint8_t *p, size_t remaining, int selector, record *r)
{
    static const uint8_t journal_magic[8] = {'B','H','J','N','L','2',0,0};
    static const uint8_t selector_magic[8] = {'B','H','S','E','L','2',0,0};
    size_t total, names, version_offset = selector ? 204U : 244U;
    size_t tuple_offset = selector ? 32U : 72U;
    size_t state_offset = selector ? 72U : 112U;
    size_t content_offset = selector ? 76U : 116U;
    if (remaining < 16) { return selector ? "selector_truncated" : "record_truncated"; }
    if (memcmp(p, selector ? selector_magic : journal_magic, 8) != 0) {
        return selector ? "selector_magic" : "record_magic";
    }
    if (be(p + 8, 2) != 2) { return selector ? "selector_version" : "record_version"; }
    if (p[10] != 1 && (selector || p[10] != 2)) { return selector ? "selector_type" : "record_type"; }
    if (p[11] != 0) { return selector ? "selector_flags" : "record_flags"; }
    total = (size_t)be(p + 12, 4);
    if (total < version_offset + 33 || total > version_offset + 96 ||
        (selector && total != remaining)) { return selector ? "selector_length" : "record_length"; }
    if (total > remaining) { return "record_truncated"; }
    names = p[state_offset + 1];
    if (names == 0 || names > 64 || total != version_offset + names + 32) {
        return selector ? "selector_length" : "record_length";
    }
    if (!zero(p + state_offset + 2, 2)) { return selector ? "selector_reserved" : "record_reserved"; }
    if (!version_valid(p + version_offset, names)) { return selector ? "selector_version_id" : "record_version_id"; }
    if (!digest_valid(p, total, selector)) { return selector ? "selector_integrity" : "record_integrity"; }
    memset(r, 0, sizeof(*r));
    memcpy(r->tuple.installation_id, p + tuple_offset, 32);
    r->tuple.epoch = be(p + tuple_offset + 32, 8);
    r->tuple.key_state = p[state_offset];
    memcpy(r->tuple.policy_digest, p + content_offset, 32);
    memcpy(r->tuple.manifest_digest, p + content_offset + 32, 32);
    memcpy(r->tuple.new_key_id, p + content_offset + 64, 32);
    memcpy(r->tuple.version_id, p + version_offset, names);
    r->tuple.version_length = names;
    r->tx = p + (selector ? 16 : 56);
    r->intent = p + content_offset + 96;
    r->digest = p + total - 32;
    r->previous = selector ? NULL : p + 24;
    r->sequence = selector ? 0 : be(p + 16, 8);
    r->type = p[10];
    r->length = total;
    return NULL;
}

/* These explicit independent comparisons are also the source mutation sites.
 * No mutation flag, bypass or test-only comparison exists in the shipped API. */
static const char *candidate_mismatch(const bh_journal_candidate *c,
                                      const bh_journal_candidate *a)
{
    if (memcmp(c->installation_id, a->installation_id, 32) != 0) { return "candidate_install_mismatch"; }
    if (c->epoch != a->epoch) { return "candidate_epoch_mismatch"; }
    if (c->key_state != a->key_state) { return "candidate_state_mismatch"; }
    if (memcmp(c->policy_digest, a->policy_digest, 32) != 0) { return "candidate_policy_mismatch"; }
    if (memcmp(c->manifest_digest, a->manifest_digest, 32) != 0) { return "candidate_manifest_mismatch"; }
    if (c->version_length != a->version_length || memcmp(c->version_id, a->version_id, c->version_length) != 0) { return "candidate_version_mismatch"; }
    if (memcmp(c->new_key_id, a->new_key_id, 32) != 0) { return "candidate_new_key_mismatch"; }
    return NULL;
}

/* Persisted tuple comparisons intentionally do not share candidate mutation sites. */
static int tuple_equal(const record *a, const record *b)
{
    return memcmp(a->tx, b->tx, 16) == 0 &&
        memcmp(a->tuple.installation_id, b->tuple.installation_id, 32) == 0 &&
        a->tuple.epoch == b->tuple.epoch && a->tuple.key_state == b->tuple.key_state &&
        memcmp(a->tuple.policy_digest, b->tuple.policy_digest, 32) == 0 &&
        memcmp(a->tuple.manifest_digest, b->tuple.manifest_digest, 32) == 0 &&
        memcmp(a->tuple.new_key_id, b->tuple.new_key_id, 32) == 0 &&
        a->tuple.version_length == b->tuple.version_length &&
        memcmp(a->tuple.version_id, b->tuple.version_id, a->tuple.version_length) == 0;
}

static int transition(uint8_t previous, uint8_t next)
{
    return (previous == 1 && (next == 1 || next == 2)) ||
        ((previous == 2 || previous == 3) && next == 3);
}

static const char *bounds(const bh_journal_candidate *c, const bh_journal_parameters *p)
{
    if (c->key_state < 1 || c->key_state > 3) { return "key_state"; }
    if (c->epoch == 0) { return "epoch"; }
    if (c->key_state == 1 && (c->epoch >= p->threshold_t || !zero(c->new_key_id, 32))) { return "old_bound"; }
    if (c->key_state == 2 && (c->epoch != p->threshold_t || memcmp(c->new_key_id, p->new_key_id, 32) != 0)) { return "armed_bound"; }
    /* Strict greater-than avoids threshold+1 overflow. */
    if (c->key_state == 3 && (c->epoch <= p->threshold_t || memcmp(c->new_key_id, p->new_key_id, 32) != 0)) { return "new_bound"; }
    return NULL;
}

static bh_journal_observation observation(bh_journal_outcome outcome,
                                          const char *diagnosis, const char *reason)
{
    bh_journal_observation result = {outcome, diagnosis, reason, 1, 0U, 0U, 0U};
    result.off = outcome != BH_JOURNAL_CONSISTENT_ONLY && outcome != BH_JOURNAL_CANDIDATE_ELIGIBLE_ONLY;
    return result;
}

static bh_journal_observation unavailable(const char *diagnosis)
{
    return observation(BH_JOURNAL_UNAVAILABLE, diagnosis, "persisted_state_unavailable");
}

bh_journal_observation bh_journal_observe(
    bh_journal_snapshot journal, bh_journal_snapshot selector,
    const bh_journal_parameters *parameters, bh_journal_action action,
    const bh_journal_candidate *candidate)
{
    size_t offsets[BH_JOURNAL_MAX_RECORDS];
    size_t count = 0, offset = 0, i, k;
    record current, pending, active, selected;
    int has_pending = 0, has_active = 0;
    const uint8_t *previous = NULL;
    const char *error;
    const char *diagnosis = "exact_active_selector";
    if (!journal.present) { return unavailable("journal_missing"); }
    if (!selector.present) { return unavailable("selector_missing"); }
    if (journal.present != 1 || selector.present != 1 ||
        (journal.length != 0 && journal.bytes == NULL) ||
        (selector.length != 0 && selector.bytes == NULL)) { return unavailable("snapshot_invalid"); }
    if (parameters == NULL || parameters->threshold_t == 0 ||
        parameters->threshold_t == UINT64_MAX ||
        zero(parameters->installation_id, 32) || zero(parameters->new_key_id, 32)) { return unavailable("parameters_invalid"); }
    if (journal.length == 0 || journal.length > BH_JOURNAL_MAX_BYTES) { return unavailable("journal_size"); }
    /* First pass validates all physical records before semantic traversal. This
     * preserves the frozen count/truncation diagnosis and never accepts a prefix. */
    while (offset < journal.length) {
        if (count == BH_JOURNAL_MAX_RECORDS) { return unavailable("record_count"); }
        error = parse(journal.bytes + offset, journal.length - offset, 0, &current);
        if (error != NULL) { return unavailable(error); }
        offsets[count++] = offset;
        offset += current.length; /* parse proved length <= remaining. */
    }
    if (count < 2) { return unavailable("missing_seed"); }
    for (i = 0; i < count; ++i) {
        error = parse(journal.bytes + offsets[i], journal.length - offsets[i], 0, &current);
        if (error != NULL) { return unavailable(error); }
        if (current.sequence != i + 1) { return unavailable("sequence"); }
        if ((previous == NULL && !zero(current.previous, 32)) ||
            (previous != NULL && memcmp(previous, current.previous, 32) != 0)) { return unavailable("previous_digest"); }
        previous = current.digest;
        if (memcmp(current.tuple.installation_id, parameters->installation_id, 32) != 0) { return unavailable("installation_mismatch"); }
        if (zero(current.tx, 16)) { return unavailable("zero_transaction"); }
        if (zero(current.tuple.policy_digest, 32) || zero(current.tuple.manifest_digest, 32)) { return unavailable("zero_content_digest"); }
        error = bounds(&current.tuple, parameters);
        if (error != NULL) { return unavailable(error); }
        if (current.type == 1) {
            if (has_pending) { return unavailable("duplicate_intent"); }
            if (!zero(current.intent, 32)) { return unavailable("intent_field"); }
            for (k = 0; k < i; ++k) {
                const uint8_t *prior = journal.bytes + offsets[k];
                if (prior[10] == 1 && memcmp(current.tx, prior + 56, 16) == 0) { return unavailable("transaction_reuse"); }
            }
            if (!has_active) {
                if (i != 0 || current.tuple.key_state != 1) { return unavailable("seed_state"); }
            } else {
                if (current.tuple.epoch <= active.tuple.epoch) { return unavailable("epoch_not_advanced"); }
                if (!transition(active.tuple.key_state, current.tuple.key_state)) { return unavailable("state_transition"); }
            }
            pending = current;
            has_pending = 1;
        } else {
            if (!has_pending) { return unavailable("active_without_intent"); }
            if (memcmp(current.intent, pending.digest, 32) != 0) { return unavailable("intent_digest"); }
            if (!tuple_equal(&current, &pending)) { return unavailable("active_tuple"); }
            if (current.sequence != pending.sequence + 1) { return unavailable("active_sequence"); }
            active = current;
            has_active = 1;
            has_pending = 0;
        }
    }
    if (!has_active) { return unavailable("missing_seed_active"); }
    if (selector.length > BH_SELECTOR_MAX_BYTES) { return unavailable("selector_length"); }
    error = parse(selector.bytes, selector.length, 1, &selected);
    if (error != NULL) { return unavailable(error); }
    if (memcmp(selected.tuple.installation_id, parameters->installation_id, 32) != 0) { return unavailable("selector_installation"); }
    if (has_pending) {
        int old_match = tuple_equal(&selected, &active) && memcmp(selected.intent, active.intent, 32) == 0;
        int new_match = tuple_equal(&selected, &pending) && memcmp(selected.intent, pending.digest, 32) == 0;
        if (!old_match && !new_match) { return unavailable("selector_tuple"); }
        return observation(BH_JOURNAL_OFF_PENDING, "pending_intent", "pending_intent");
    }
    if (!tuple_equal(&selected, &active) || memcmp(selected.intent, active.intent, 32) != 0) { return unavailable("selector_tuple"); }
    if (action == BH_JOURNAL_STARTUP_RECOVER) { return observation(BH_JOURNAL_CONSISTENT_ONLY, diagnosis, diagnosis); }
    error = NULL;
    if (candidate == NULL) { error = "candidate_missing"; }
    else if (candidate->epoch == 0) { error = "candidate_epoch_encoding"; }
    else if (candidate->key_state < 1 || candidate->key_state > 3) { error = "candidate_state_encoding"; }
    else if (!version_valid(candidate->version_id, candidate->version_length)) { error = "candidate_version_encoding"; }
    else if (zero(candidate->installation_id, 32) || zero(candidate->policy_digest, 32) || zero(candidate->manifest_digest, 32)) { error = "candidate_zero_digest"; }
    if (error != NULL) { return observation(BH_JOURNAL_OFF_REJECT, diagnosis, error); }
    if (action == BH_JOURNAL_SAME_EPOCH_CANDIDATE) {
        error = candidate_mismatch(candidate, &active.tuple);
        return observation(error == NULL ? BH_JOURNAL_CONSISTENT_ONLY : BH_JOURNAL_OFF_REJECT,
                           diagnosis, error == NULL ? "exact_same_epoch_candidate" : error);
    }
    if (action != BH_JOURNAL_ADVANCE_CANDIDATE) { return observation(BH_JOURNAL_OFF_REJECT, diagnosis, "action_unknown"); }
    if (memcmp(candidate->installation_id, active.tuple.installation_id, 32) != 0) { error = "candidate_install_mismatch"; }
    else if (candidate->epoch <= active.tuple.epoch) { error = "candidate_epoch_not_advanced"; }
    else {
        const char *bound = bounds(candidate, parameters);
        if (bound != NULL) {
            error = candidate->key_state == 1 ? "candidate_old_bound" :
                (candidate->key_state == 2 ? "candidate_armed_bound" : "candidate_new_bound");
        } else if (!transition(active.tuple.key_state, candidate->key_state)) { error = "candidate_state_transition"; }
        else if (count > BH_JOURNAL_MAX_RECORDS - 2 ||
                 2 * (276 + candidate->version_length) > BH_JOURNAL_MAX_BYTES - journal.length) { error = "candidate_capacity"; }
    }
    return observation(error == NULL ? BH_JOURNAL_CANDIDATE_ELIGIBLE_ONLY : BH_JOURNAL_OFF_REJECT,
                       diagnosis, error == NULL ? "candidate_precheck_only" : error);
}
