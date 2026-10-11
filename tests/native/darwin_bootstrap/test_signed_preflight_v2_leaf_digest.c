/* Off-only retained-leaf digest diagnostic. Reuse the exact fake OS and
 * startup bridge harness; only this test image enables the candidate seam. */
#ifndef BH_TX_LEAF_DIGEST_TEST
#error BH_TX_LEAF_DIGEST_TEST must be enabled for this test image
#endif
#define BH_TX_CODEC_TEST 1
#define main bh_prior_transaction_test_main
#include "test_signed_preflight_v2_transaction.c"
#undef main

#ifdef BH_TX_LEAF_RED_STUB
struct bh_tx_leaf_claim { uint64_t epoch; uint32_t key_state; };
static unsigned leaf_red_stub_hits;
uint32_t bh_v2_transaction_observe_leaf_digests(struct bh_v2_transaction **owner,
    const struct bh_tx_leaf_claim *claim, struct bh_tx_result *result) {
    (void)owner; (void)claim; (void)result;
    ++leaf_red_stub_hits;
    return BH_TX_REJECTED;
}
#endif

struct leaf_fixture_data {
    const char *name;
    const uint8_t *journal; size_t journal_length;
    const uint8_t *selector; size_t selector_length;
    uint64_t epoch; uint32_t key_state; const char *version;
    size_t policy_length, manifest_length;
    uint8_t policy_digest[32], manifest_digest[32];
};
struct leaf_case_data { const char *name; unsigned variants; };
#include "leaf_vectors.h"

static uint8_t leaf_policy_bytes[65584], leaf_signature_bytes[64],
    leaf_manifest_bytes[65552];
static struct {
    int mutate_leaf; size_t mutate_at;
    int embed_nul_leaf;
    int backing_change_leaf;
    const char *version;
    int version_count;
    int parent_uppercase;
    int mutate_install_after_begin;
    int stop_after;
    int startup_mutation;
} leaf_config;
static void leaf_config_default(void) {
    memset(&leaf_config,0,sizeof(leaf_config));
    leaf_config.mutate_leaf=-1;
    leaf_config.embed_nul_leaf=-1;
    leaf_config.backing_change_leaf=-1;
    leaf_config.version_count=-1;
}
static struct {
    unsigned calls, errors, hash_calls, hash_fault_at, hash_fault_kind;
    bh_journal_observation forced;
    int force_outcome;
    bh_journal_outcome spy_outcome;
    bh_journal_outcome real_outcome;
    bh_journal_outcome observed_outcome;
    bh_journal_candidate candidate;
    bh_journal_candidate expected_candidate;
    bh_journal_parameters parameters;
    bh_journal_snapshot journal, selector;
    const struct leaf_fixture_data *fixture;
    struct bh_tx_leaf_claim *claim_source;
    int claim_mutation;
} leaf_probe;

unsigned char *bh_test_tx_sha256(const void *data, CC_LONG length, unsigned char *digest) {
    ++leaf_probe.hash_calls;
    if (leaf_probe.hash_calls == 1 && leaf_probe.claim_mutation && leaf_probe.claim_source) {
        if (leaf_probe.claim_mutation == 1) leaf_probe.claim_source->epoch += 1;
        else leaf_probe.claim_source->key_state = 2;
    }
    if (!digest || !data || !leaf_probe.fixture) ++leaf_probe.errors;
    if (leaf_probe.hash_calls == 1) {
        if (data != f.blocks[1].ptr || length != leaf_probe.fixture->policy_length)
            ++leaf_probe.errors;
    } else if (leaf_probe.hash_calls == 2) {
        if (data != f.blocks[3].ptr || length != leaf_probe.fixture->manifest_length)
            ++leaf_probe.errors;
    } else ++leaf_probe.errors;
    if (leaf_probe.hash_calls == leaf_probe.hash_fault_at && leaf_probe.hash_fault_kind == 1)
        return NULL;
    unsigned char *actual = CC_SHA256(data,length,digest);
    if (leaf_probe.hash_calls == leaf_probe.hash_fault_at && leaf_probe.hash_fault_kind == 2)
        return NULL;
    if (leaf_probe.hash_calls == leaf_probe.hash_fault_at && leaf_probe.hash_fault_kind == 3)
        return digest + 1;
    if (leaf_probe.hash_calls == leaf_probe.hash_fault_at && leaf_probe.hash_fault_kind == 4) {
        memset(digest,0,32); return digest;
    }
    return actual;
}

static bh_journal_observation leaf_candidate_wrap(bh_journal_snapshot journal,
    bh_journal_snapshot selector, const bh_journal_parameters *parameters,
    bh_journal_action action, const bh_journal_candidate *candidate) {
    ++leaf_probe.calls;
    if (!leaf_probe.fixture || !parameters || !candidate ||
        action != BH_JOURNAL_SAME_EPOCH_CANDIDATE ||
        parameters == codec_spy.source ||
        memcmp(parameters,&leaf_probe.parameters,sizeof(*parameters)) ||
        journal.bytes != f.blocks[5].ptr || journal.length != leaf_probe.journal.length || !journal.present ||
        selector.bytes != f.blocks[6].ptr || selector.length != leaf_probe.selector.length || !selector.present ||
        memcmp(journal.bytes,leaf_probe.journal.bytes,journal.length) ||
        memcmp(selector.bytes,leaf_probe.selector.bytes,selector.length)) {
        ++leaf_probe.errors;
    }
    if (!candidate || (const void *)candidate == (const void *)leaf_probe.claim_source ||
        memcmp(candidate,&leaf_probe.expected_candidate,sizeof(*candidate)))
        ++leaf_probe.errors;
    if (candidate) leaf_probe.candidate = *candidate;
#ifdef BH_TX_CODEC_SPY
    bh_journal_observation observed=leaf_probe.force_outcome ? leaf_probe.forced :
        (bh_journal_observation){leaf_probe.spy_outcome,"spy","spy",0,99,77,66};
    leaf_probe.observed_outcome=observed.outcome;
    return observed;
#else
    bh_journal_observation real = bh_test_real_journal_observe(journal,selector,
        parameters,action,candidate);
    leaf_probe.real_outcome = real.outcome;
    bh_journal_observation observed=leaf_probe.force_outcome ? leaf_probe.forced : real;
    leaf_probe.observed_outcome=observed.outcome;
    return observed;
#endif
}

static void leaf_fill(const struct leaf_fixture_data *fixture) {
    for (size_t i=0; i<fixture->policy_length; ++i)
        leaf_policy_bytes[i] = (uint8_t)((17u*i+3u)%256u);
    memset(leaf_signature_bytes,0x55,sizeof(leaf_signature_bytes));
    for (size_t i=0; i<fixture->manifest_length; ++i)
        leaf_manifest_bytes[i] = (uint8_t)((29u*i+7u)%256u);
    leaf_pread_bytes[0]=leaf_policy_bytes; leaf_pread_lengths[0]=fixture->policy_length;
    leaf_pread_bytes[1]=leaf_signature_bytes; leaf_pread_lengths[1]=sizeof(leaf_signature_bytes);
    leaf_pread_bytes[2]=leaf_manifest_bytes; leaf_pread_lengths[2]=fixture->manifest_length;
}

static int leaf_fixture_hashes_are_pinned(const struct leaf_fixture_data *fixture) {
    unsigned char policy[32], manifest[32];
    return CC_SHA256(leaf_policy_bytes,(CC_LONG)fixture->policy_length,policy) == policy &&
        CC_SHA256(leaf_manifest_bytes,(CC_LONG)fixture->manifest_length,manifest) == manifest &&
        !memcmp(policy,fixture->policy_digest,32) && !memcmp(manifest,fixture->manifest_digest,32);
}

static int leaf_complete_startup(const struct leaf_fixture_data *fixture,
    struct bh_v2_transaction **owner, struct bh_tx_result *result,
    bh_journal_parameters *parameters) {
    const char *version=leaf_config.version ? leaf_config.version : fixture->version;
    if (f.alloc_live != 6 || f.blocks[5].size != fixture->journal_length ||
        f.blocks[6].size != fixture->selector_length ||
        memcmp(f.blocks[5].ptr,fixture->journal,fixture->journal_length) ||
        memcmp(f.blocks[6].ptr,fixture->selector,fixture->selector_length)) return 0;
    memset(parameters,0,sizeof(*parameters));
    memset(parameters->installation_id,0x10,32);
    memset(parameters->new_key_id,0xa5,32);
    parameters->threshold_t=7;
    memset(&codec_spy,0,sizeof(codec_spy));
    codec_spy.journal=(bh_journal_snapshot){fixture->journal,fixture->journal_length,1};
    codec_spy.selector=(bh_journal_snapshot){fixture->selector,fixture->selector_length,1};
    codec_spy.real_expected=BH_JOURNAL_CONSISTENT_ONLY;
    codec_spy.real_diagnosis="exact_active_selector";
    codec_spy.outcome=BH_JOURNAL_CONSISTENT_ONLY;
    codec_spy.mutation=leaf_config.startup_mutation;
    bh_journal_parameters original_parameters=*parameters;
    memset(result,0,sizeof(*result));
    if (codec_call(owner,parameters,result) != BH_TX_PREPARED_UNTRUSTED ||
        codec_spy.calls != 1 || codec_spy.errors || !safe_result(result) || f.alloc_live != 6)
        return 0;
    leaf_probe.journal=(bh_journal_snapshot){fixture->journal,fixture->journal_length,1};
    leaf_probe.selector=(bh_journal_snapshot){fixture->selector,fixture->selector_length,1};
    leaf_probe.parameters=original_parameters;
    memset(&leaf_probe.expected_candidate,0,sizeof(leaf_probe.expected_candidate));
    memcpy(leaf_probe.expected_candidate.installation_id,original_parameters.installation_id,32);
    leaf_probe.expected_candidate.epoch=fixture->epoch;
    leaf_probe.expected_candidate.key_state=(uint8_t)fixture->key_state;
    if (fixture->key_state != 1u)
        memcpy(leaf_probe.expected_candidate.new_key_id,original_parameters.new_key_id,32);
    leaf_probe.expected_candidate.version_length=strlen(version);
    memcpy(leaf_probe.expected_candidate.version_id,version,
        leaf_probe.expected_candidate.version_length);
    if (CC_SHA256(f.blocks[1].ptr,(CC_LONG)f.blocks[1].size,
                  leaf_probe.expected_candidate.policy_digest) != leaf_probe.expected_candidate.policy_digest ||
        CC_SHA256(f.blocks[3].ptr,(CC_LONG)f.blocks[3].size,
                  leaf_probe.expected_candidate.manifest_digest) != leaf_probe.expected_candidate.manifest_digest)
        return 0;
    memset(result,0,sizeof(*result));
    return !f.errors;
}

static int leaf_prepare(const struct leaf_fixture_data *fixture,
    struct bh_v2_transaction **owner, struct bh_tx_result *result,
    bh_journal_parameters *parameters) {
    reset(); expected_begin();
    memset(&codec_spy,0,sizeof(codec_spy));
    memset(&leaf_probe,0,sizeof(leaf_probe)); leaf_probe.fixture=fixture;
    leaf_probe.spy_outcome=BH_JOURNAL_CONSISTENT_ONLY;
    leaf_fill(fixture);
    if (!leaf_fixture_hashes_are_pinned(fixture)) return 0;
    if (leaf_config.embed_nul_leaf == 0) leaf_policy_bytes[2]=0;
    if (leaf_config.embed_nul_leaf == 2) leaf_manifest_bytes[2]=0;
    if (leaf_config.mutate_leaf >= 0 && leaf_config.mutate_leaf < 3) {
        int leaf=leaf_config.mutate_leaf;
        if (leaf_config.mutate_at >= leaf_pread_lengths[leaf]) return 0;
        ((uint8_t *)leaf_pread_bytes[leaf])[leaf_config.mutate_at] ^= 0x40;
    }
    f.meta[POLICY].st_size=(off_t)fixture->policy_length;
    f.meta[MANIFEST].st_size=(off_t)fixture->manifest_length;
    f.meta[FLOOR].st_size=(off_t)fixture->journal_length;
    f.meta[SELECTOR].st_size=(off_t)fixture->selector_length;
    f.codec_bytes[0]=fixture->journal; f.codec_lengths[0]=fixture->journal_length;
    f.codec_bytes[1]=fixture->selector; f.codec_lengths[1]=fixture->selector_length;
    const char *version=leaf_config.version ? leaf_config.version : fixture->version;
    if (strlen(version) >= sizeof(leaf_version_name)) return 0;
    memset(leaf_version_name,0,sizeof(leaf_version_name));
    memcpy(leaf_version_name,version,strlen(version));
    struct bh_tx_install descriptor=install();
    if (leaf_config.version_count >= 0) descriptor.version.count=(uint32_t)leaf_config.version_count;
    leaf_version_count_zero=descriptor.version.count == 0;
    leaf_parent_uppercase=leaf_config.parent_uppercase;
    if (leaf_config.parent_uppercase) strcpy(descriptor.version.components[0],"Versions");
    if (descriptor.version.count == 4) {
        strcpy(descriptor.version.components[1],version);
        strcpy(descriptor.version.components[2],version);
    }
    if (descriptor.version.count > 0)
        strcpy(descriptor.version.components[descriptor.version.count-1],version);
    if (bh_v2_transaction_begin(9,&descriptor,owner,result) != BH_TX_PREPARED_UNTRUSTED ||
        !*owner || !retention() || f.alloc_live != 1) return 0;
    if (leaf_config.version_count < 0 && f.count != expected_count) return 0;
    if (leaf_config.mutate_install_after_begin && descriptor.version.count > 0)
        strcpy(descriptor.version.components[descriptor.version.count-1],"release-8");
    if (leaf_config.stop_after == 1) { memset(result,0,sizeof(*result)); return 1; }
    memset(result,0,sizeof(*result));
    if (observe_call(owner,result) != BH_TX_PREPARED_UNTRUSTED ||
        !original_leaf_reads() || f.alloc_live != 4) return 0;
    for (int i=0; i<3; ++i)
        if (f.blocks[i+1].size != leaf_pread_lengths[i] ||
            memcmp(f.blocks[i+1].ptr,leaf_pread_bytes[i],leaf_pread_lengths[i])) return 0;
    if (leaf_config.backing_change_leaf >= 0 && leaf_config.backing_change_leaf < 3)
        ((uint8_t *)leaf_pread_bytes[leaf_config.backing_change_leaf])[0] ^= 0x80;
    if (leaf_config.backing_change_leaf == 3) {
        leaf_policy_bytes[0] ^= 0x80;
        leaf_manifest_bytes[0] ^= 0x80;
    }
    if (leaf_config.stop_after == 2) { memset(result,0,sizeof(*result)); return 1; }
    memset(result,0,sizeof(*result));
    if (local_state_call(owner,result) != BH_TX_PREPARED_UNTRUSTED ||
        !state_original_reads() ||
        (descriptor.version.count != 0 && !state_full_trace()) || f.alloc_live != 6) return 0;
    if (f.blocks[5].size != fixture->journal_length ||
        f.blocks[6].size != fixture->selector_length ||
        memcmp(f.blocks[5].ptr,fixture->journal,fixture->journal_length) ||
        memcmp(f.blocks[6].ptr,fixture->selector,fixture->selector_length)) return 0;
    if (leaf_config.stop_after == 3) { memset(result,0,sizeof(*result)); return 1; }
    return leaf_complete_startup(fixture,owner,result,parameters);
}

#ifdef BH_TX_LEAF_RED_STUB
static int leaf_positive_red(void) {
    current="LeafDigest_WhenActiveTupleMatches_RemainsUntrusted"; variant=0;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0};
    bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) {
        fprintf(stderr,"SETUP leaf positive failed before candidate stage\n"); return 2;
    }
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    leaf_probe.claim_source=&claim;
    int event_count=f.count, frees=f.frees;
    uint32_t status=bh_v2_transaction_observe_leaf_digests(&owner,&claim,&result);
    printf("LEAF RED prior=BEGIN+RETAINED+LOCAL_STATE+STARTUP_CONSISTENT expected=%u actual=%u stub_hits=%u hash=%u candidate=%u\n",
        BH_TX_PREPARED_UNTRUSTED,status,
#ifdef BH_TX_LEAF_RED_STUB
        leaf_red_stub_hits,
#else
        0u,
#endif
        leaf_probe.hash_calls,leaf_probe.calls);
    if (status != BH_TX_PREPARED_UNTRUSTED) {
        fprintf(stderr,"ASSERT LeafDigest_WhenActiveTupleMatches_RemainsUntrusted variant=0: expected PREPARED_UNTRUSTED actual=%u\n",status);
        return 1;
    }
    if (result.status != status || !safe_result(&result) ||
        !owner || leaf_probe.hash_calls != 2 || leaf_probe.calls != 1 ||
        leaf_probe.errors || f.count != event_count || f.frees != frees || f.alloc_live != 6) {
        fprintf(stderr,"ASSERT LeafDigest_WhenActiveTupleMatches_RemainsUntrusted variant=0: positive ledger/tuple mismatch\n");
        return 1;
    }
    memset(&result,0,sizeof(result));
    if (bh_v2_transaction_abort(&owner,&result) != BH_TX_ABORTED || owner ||
        result.status != BH_TX_ABORTED || !safe_result(&result) ||
        f.alloc_live || f.errors || !borrowed_preserved()) {
        fprintf(stderr,"ASSERT LeafDigest_WhenActiveTupleMatches_RemainsUntrusted variant=0: abort mismatch\n");
        return 1;
    }
    return 0;
}
#endif

#ifndef BH_TX_LEAF_RED_STUB
static int leaf_expect(struct bh_v2_transaction **owner,
    struct bh_tx_leaf_claim *claim, struct bh_tx_result *result,
    uint32_t want, unsigned hashes, unsigned candidate_calls, int drains) {
    int ok=1, events=f.count, frees=f.frees, allocations=f.allocations;
    size_t payload=f.payload_live;
    leaf_probe.claim_source=claim;
    if (claim) {
        leaf_probe.expected_candidate.epoch=claim->epoch;
        leaf_probe.expected_candidate.key_state=(uint8_t)claim->key_state;
        memset(leaf_probe.expected_candidate.new_key_id,0,32);
        if (claim->key_state != 1u)
            memcpy(leaf_probe.expected_candidate.new_key_id,leaf_probe.parameters.new_key_id,32);
    }
    memset(result,0,sizeof(*result));
    uint32_t got=bh_v2_transaction_observe_leaf_digests(owner,claim,result);
    printf("LEAF %s variant=%d expected=%u actual=%u sha=%u candidate=%u frees=%d\n",
        current,variant,want,got,leaf_probe.hash_calls,leaf_probe.calls,f.frees-frees);
    REQUIRE(got == want && result->status == want && safe_result(result));
    REQUIRE(owner && *owner && leaf_probe.hash_calls == hashes &&
            leaf_probe.calls == candidate_calls && !leaf_probe.errors);
    REQUIRE(f.allocations == allocations && f.frees == frees+(drains ? 5 : 0) &&
            codec_no_io(events,drains ? 5 : 0));
    REQUIRE(f.alloc_live == (drains ? 1 : 6) &&
            (drains ? state_all_buffers_freed() : f.payload_live == payload));
    REQUIRE(!f.errors && borrowed_preserved());
    return ok;
}

static int leaf_finish(struct bh_v2_transaction **owner, struct bh_tx_result *result) {
    int ok=1, cursor=f.count;
    memset(result,0,sizeof(*result));
    REQUIRE(bh_v2_transaction_abort(owner,result) == BH_TX_ABORTED);
    REQUIRE(*owner == NULL && result->status == BH_TX_ABORTED && safe_result(result));
    REQUIRE(!f.alloc_live && !owned_live() && borrowed_preserved() &&
            local_state_cleanup_order(cursor) && !f.errors);
    for (int i=0; i<f.block_count; ++i) REQUIRE(f.blocks[i].frees == 1);
    return ok;
}

static int leaf_standard_positive(int fixture_index) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[fixture_index];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) {
        fprintf(stderr,"SETUP %s variant=%d prerequisites failed\n",current,variant);
        return 0;
    }
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_CONSISTENT_ONLY);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_codec_outcome_matches(bh_journal_outcome observed,
    bh_journal_outcome expected) {
    return observed == expected;
}

static int leaf_changed_leaf(int leaf, size_t offset, uint32_t want,
    bh_journal_outcome codec_outcome) {
    int ok=1;
    leaf_config_default();
    leaf_config.mutate_leaf=leaf;
    leaf_config.mutate_at=offset;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) {
        fprintf(stderr,"SETUP %s variant=%d changed leaf failed\n",current,variant);
        return 0;
    }
    leaf_probe.spy_outcome=codec_outcome;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,want,2,1,want != BH_TX_PREPARED_UNTRUSTED));
    REQUIRE(leaf_codec_outcome_matches(leaf_probe.observed_outcome,codec_outcome));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_change_after_nul(int which) {
    int ok=1;
    int leaf=which == 0 ? 0 : 2;
    leaf_config_default();
    leaf_config.mutate_leaf=leaf;
    leaf_config.mutate_at=which == 0 ? 48u : 16u;
    if (which == 1) leaf_config.embed_nul_leaf=2;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    const unsigned char *snapshot=f.blocks[leaf == 0 ? 1 : 3].ptr;
    REQUIRE(memchr(snapshot,0,leaf_config.mutate_at) != NULL);
    leaf_probe.spy_outcome=BH_JOURNAL_OFF_REJECT;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_REJECTED,2,1,1));
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_OFF_REJECT);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_caller_adjacent_digest(int which) {
    int ok=1;
    leaf_config_default();
    leaf_config.mutate_leaf=which == 0 ? 0 : 2;
    leaf_config.mutate_at=which == 0 ? 48u : 16u;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct {
        struct bh_tx_leaf_claim claim;
        unsigned char caller_policy_digest[32], caller_manifest_digest[32];
    } hostile={0};
    hostile.claim.epoch=fixture->epoch;
    hostile.claim.key_state=fixture->key_state;
    memcpy(hostile.caller_policy_digest,fixture->policy_digest,32);
    memcpy(hostile.caller_manifest_digest,fixture->manifest_digest,32);
    leaf_probe.spy_outcome=BH_JOURNAL_OFF_REJECT;
    REQUIRE(leaf_expect(&owner,&hostile.claim,&result,BH_TX_REJECTED,2,1,1));
    REQUIRE(!memcmp(hostile.caller_policy_digest,fixture->policy_digest,32) &&
            !memcmp(hostile.caller_manifest_digest,fixture->manifest_digest,32));
    REQUIRE(which == 0 ? memcmp(leaf_probe.candidate.policy_digest,fixture->policy_digest,32) != 0 :
            memcmp(leaf_probe.candidate.manifest_digest,fixture->manifest_digest,32) != 0);
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_OFF_REJECT);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_backing_change_after_capture(int which) {
    int ok=1;
    leaf_config_default();
    leaf_config.backing_change_leaf=which == 0 ? 0 : which == 1 ? 2 : 3;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    REQUIRE(which == 0 ? memcmp(f.blocks[1].ptr,leaf_policy_bytes,fixture->policy_length) != 0 :
            which == 1 ? memcmp(f.blocks[3].ptr,leaf_manifest_bytes,fixture->manifest_length) != 0 :
            memcmp(f.blocks[1].ptr,leaf_policy_bytes,fixture->policy_length) != 0 &&
            memcmp(f.blocks[3].ptr,leaf_manifest_bytes,fixture->manifest_length) != 0);
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_CONSISTENT_ONLY);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_claim_invalid(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    if (which == 0) claim.epoch=0;
    else claim.key_state=which == 1 ? 0u : which == 2 ? 4u : 256u;
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_REJECTED,0,0,1));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_claim_mismatch(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[which == 3 ? 1 : 0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    if (which == 0) --claim.epoch;
    else if (which == 1) ++claim.epoch;
    else if (which == 2) claim.key_state=2;
    else claim.key_state=1;
    leaf_probe.spy_outcome=BH_JOURNAL_OFF_REJECT;
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_REJECTED,2,1,1));
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_OFF_REJECT);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_version_mismatch(int which) {
    int ok=1;
    leaf_config_default();
    leaf_config.version=which == 0 ? "release-8" : "release_7";
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    leaf_probe.spy_outcome=BH_JOURNAL_OFF_REJECT;
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_REJECTED,2,1,1));
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_OFF_REJECT);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_invalid_version(int which) {
    int ok=1;
    static const char *const spellings[6]={
        "release-7","Release-7","release.7","-release7","release7_","release-7-"};
    leaf_config_default();
    leaf_config.version=spellings[which];
    if (which == 0) leaf_config.version_count=0;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) {
        fprintf(stderr,"SETUP %s variant=%d invalid version path not acquired\n",current,variant);
        return 0;
    }
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_REJECTED,0,0,1));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_valid_version_path(int which) {
    int ok=1;
    leaf_config_default();
    if (which == 2) leaf_config.version_count=4;
    if (which == 3) leaf_config.parent_uppercase=1;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[which < 2 ? which+7 : 0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_CONSISTENT_ONLY);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_copied_install(void) {
    int ok=1;
    leaf_config_default(); leaf_config.mutate_install_after_begin=1;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
    REQUIRE(leaf_probe.candidate.version_length == strlen(fixture->version) &&
            !memcmp(leaf_probe.candidate.version_id,fixture->version,strlen(fixture->version)));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_startup_parameter_copy(int which) {
    int ok=1;
    leaf_config_default(); leaf_config.startup_mutation=which+1;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[1];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    REQUIRE(codec_spy.mutation_hits == 1);
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_CONSISTENT_ONLY);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_claim_entry_copy(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    leaf_probe.claim_mutation=which+1;
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
    REQUIRE(which == 0 ? claim.epoch == fixture->epoch+1 : claim.key_state == 2u);
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_CONSISTENT_ONLY);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_hash_fault(int which, int fault_kind, uint32_t want,
    unsigned hashes, unsigned candidate_calls) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    leaf_probe.hash_fault_at=(unsigned)which+1;
    leaf_probe.hash_fault_kind=(unsigned)fault_kind;
    if (fault_kind == 4) {
        unsigned char *expected = which == 0 ? leaf_probe.expected_candidate.policy_digest :
            leaf_probe.expected_candidate.manifest_digest;
        memset(expected,0,32);
        leaf_probe.spy_outcome=BH_JOURNAL_OFF_REJECT;
    }
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,want,hashes,candidate_calls,1));
#ifndef BH_TX_CODEC_SPY
    if (fault_kind == 4) REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_OFF_REJECT);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_snapshot_field(size_t *pointer_offset, size_t *lengths_offset) {
    const unsigned char *context=f.blocks[0].ptr;
    size_t size=f.blocks[0].size, matches=0;
    void *pointers[3]={f.blocks[1].ptr,f.blocks[2].ptr,f.blocks[3].ptr};
    for (size_t at=0; at+3*sizeof(void *)+3*sizeof(size_t)<=size; ++at) {
        if (memcmp(context+at,pointers,sizeof(pointers))) continue;
        size_t lengths[3];
        memcpy(lengths,context+at+sizeof(pointers),sizeof(lengths));
        if (lengths[0] != f.blocks[1].size || lengths[1] != f.blocks[2].size ||
            lengths[2] != f.blocks[3].size) continue;
        *pointer_offset=at;
        *lengths_offset=at+sizeof(pointers);
        ++matches;
    }
    return matches == 1;
}

static int leaf_broken_snapshot_invariant(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    size_t pointers_offset=0, lengths_offset=0;
    if (!leaf_snapshot_field(&pointers_offset,&lengths_offset)) {
        fprintf(stderr,"SETUP %s variant=%d snapshot layout not unique\n",current,variant);
        return 0;
    }
    unsigned char *context=f.blocks[0].ptr;
    int leaf=which == 0 || which == 2 || which == 3 ? 0 : 2;
    int block=leaf == 0 ? 1 : 3;
    if (which < 2) {
        void *zero=NULL;
        memcpy(context+pointers_offset+(size_t)leaf*sizeof(void *),&zero,sizeof(zero));
    } else {
        size_t invalid=which == 2 ? 48u : which == 3 ? 65585u :
            which == 4 ? 16u : 65553u;
        memcpy(context+lengths_offset+(size_t)leaf*sizeof(size_t),&invalid,sizeof(invalid));
    }
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    leaf_probe.claim_source=&claim;
    int events=f.count, frees=f.frees, allocations=f.allocations;
    memset(&result,0,sizeof(result));
    uint32_t got=bh_v2_transaction_observe_leaf_digests(&owner,&claim,&result);
    printf("LEAF %s variant=%d expected=%u actual=%u sha=%u candidate=%u frees=%d\n",
        current,variant,BH_TX_UNAVAILABLE,got,leaf_probe.hash_calls,leaf_probe.calls,f.frees-frees);
    REQUIRE(got == BH_TX_UNAVAILABLE && result.status == got && safe_result(&result));
    REQUIRE(leaf_probe.hash_calls == 0 && leaf_probe.calls == 0 && !leaf_probe.errors);
    REQUIRE(f.allocations == allocations && codec_no_io(events,which < 2 ? 4 : 5));
    REQUIRE(f.frees == frees+(which < 2 ? 4 : 5) && !f.errors);
    if (which < 2) {
        REQUIRE(f.blocks[block].alive && f.alloc_live == 2);
        bh_tx_os_free(f.blocks[block].ptr); /* test-owned detached allocation */
        REQUIRE(f.alloc_live == 1 && f.blocks[block].frees == 1);
    } else REQUIRE(f.alloc_live == 1 && state_all_buffers_freed());
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_codec_outcome(int which) {
    int ok=1;
    static const bh_journal_outcome outcomes[6] = {
        BH_JOURNAL_CONSISTENT_ONLY,BH_JOURNAL_OFF_REJECT,BH_JOURNAL_OFF_PENDING,
        BH_JOURNAL_UNAVAILABLE,BH_JOURNAL_CANDIDATE_ELIGIBLE_ONLY,(bh_journal_outcome)99};
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    leaf_probe.force_outcome=1;
    leaf_probe.forced=(bh_journal_observation){outcomes[which],"hostile","hostile",0,99,77,66};
    uint32_t want=which == 0 ? BH_TX_PREPARED_UNTRUSTED :
        which == 1 ? BH_TX_REJECTED : BH_TX_UNAVAILABLE;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,want,2,1,which != 0));
#ifndef BH_TX_CODEC_SPY
    REQUIRE(leaf_probe.real_outcome == BH_JOURNAL_CONSISTENT_ONLY);
#endif
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_startup_nonconsistent(int which, int pending) {
    int ok=1;
    static const char *const pending_names[4]={
        "crash_armed_intent_old_selector","crash_armed_intent_target_selector",
        "crash_new_only_intent_old_selector","crash_new_only_intent_target_selector"};
    static const char *const corrupt_names[4]={
        "incorrect_integrity_digest","unknown_record_type",
        "selector_policy_mismatch","selector_suffix"};
    for (int i=0; i<3; ++i) { leaf_pread_bytes[i]=NULL; leaf_pread_lengths[i]=0; }
    leaf_version_name[0]=0; leaf_version_count_zero=0; leaf_parent_uppercase=0;
    memset(&leaf_probe,0,sizeof(leaf_probe));
    const journal_case *fixture=codec_vector(pending ? pending_names[which] : corrupt_names[which]);
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0};
    if (!codec_prepare(&owner,&result,fixture,1)) return 0;
    bh_journal_parameters parameters={0};
    memset(parameters.installation_id,0x10,32);
    memset(parameters.new_key_id,0xa5,32);
    parameters.threshold_t=7;
    codec_spy.outcome=fixture->expected;
    memset(&result,0,sizeof(result));
    REQUIRE(codec_call(&owner,&parameters,&result) == BH_TX_UNAVAILABLE);
    REQUIRE(result.status == BH_TX_UNAVAILABLE && safe_result(&result) &&
            codec_spy.calls == 1 && !codec_spy.errors && state_all_buffers_freed());
    struct bh_tx_leaf_claim claim={6,1};
    memset(&result,0,sizeof(result));
    int events=f.count, frees=f.frees, allocations=f.allocations;
    REQUIRE(bh_v2_transaction_observe_leaf_digests(&owner,&claim,&result) == BH_TX_UNAVAILABLE);
    REQUIRE(result.status == BH_TX_UNAVAILABLE && safe_result(&result) &&
            f.count == events && f.frees == frees && f.allocations == allocations &&
            leaf_probe.hash_calls == 0 && leaf_probe.calls == 0);
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_structural_null(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL, *empty_owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    int events=f.count, allocations=f.allocations, frees=f.frees;
    struct bh_tx_result before=result;
    uint32_t got;
    if (which == 0) got=bh_v2_transaction_observe_leaf_digests(NULL,&claim,&result);
    else if (which == 1) got=bh_v2_transaction_observe_leaf_digests(&owner,NULL,&result);
    else if (which == 2) got=bh_v2_transaction_observe_leaf_digests(&owner,&claim,NULL);
    else got=bh_v2_transaction_observe_leaf_digests(&empty_owner,&claim,&result);
    REQUIRE(got == BH_TX_REJECTED && !memcmp(&result,&before,sizeof(result)));
    REQUIRE(owner && !empty_owner && f.count == events && f.allocations == allocations &&
            f.frees == frees && leaf_probe.hash_calls == 0 && leaf_probe.calls == 0);
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_structural_public_overlap(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    _Alignas(max_align_t) unsigned char storage[64]={0}, before[64];
    struct bh_v2_transaction **owner_arg=&owner;
    struct bh_tx_leaf_claim *claim_arg=&claim;
    struct bh_tx_result *result_arg=&result;
    if (which < 2) {
        result_arg=(struct bh_tx_result *)(void *)storage;
        owner_arg=(struct bh_v2_transaction **)(void *)(storage+(which ? 8 : 0));
        *owner_arg=owner;
    } else if (which < 4) {
        claim_arg=(struct bh_tx_leaf_claim *)(void *)storage;
        owner_arg=(struct bh_v2_transaction **)(void *)(storage+(which == 3 ? 8 : 0));
        *owner_arg=owner;
    } else {
        result_arg=(struct bh_tx_result *)(void *)storage;
        claim_arg=(struct bh_tx_leaf_claim *)(void *)(storage+(which == 5 ? 8 : 0));
        *claim_arg=claim;
    }
    memcpy(before,storage,sizeof(before));
    int events=f.count, allocations=f.allocations, frees=f.frees;
    REQUIRE(bh_v2_transaction_observe_leaf_digests(owner_arg,claim_arg,result_arg) == BH_TX_REJECTED);
    REQUIRE(!memcmp(storage,before,sizeof(storage)) && owner &&
            f.count == events && f.allocations == allocations && f.frees == frees &&
            leaf_probe.hash_calls == 0 && leaf_probe.calls == 0);
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_private_alias(int which, int snapshot_case) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    static const int blocks[5]={1,2,3,5,6};
    int slot=snapshot_case ? blocks[which%5] : 0;
    int input=snapshot_case ? which/5 : which;
    unsigned char *storage=f.blocks[slot].ptr;
    size_t logical=f.blocks[slot].size;
    size_t capacity=logical < sizeof(struct bh_tx_result) ? sizeof(struct bh_tx_result) : logical;
    unsigned char *original=malloc(capacity);
    unsigned char *before=malloc(capacity);
    if (!storage || !original || !before) abort();
    memcpy(original,storage,capacity);
    struct bh_v2_transaction **owner_arg=&owner;
    struct bh_tx_leaf_claim *claim_arg=&claim;
    struct bh_tx_result *result_arg=&result;
    if (input == 0) {
        owner_arg=(struct bh_v2_transaction **)(void *)storage;
        *owner_arg=owner;
    } else if (input == 1) {
        claim_arg=(struct bh_tx_leaf_claim *)(void *)storage;
        *claim_arg=claim;
    } else {
        result_arg=(struct bh_tx_result *)(void *)storage;
        memset(result_arg,0,sizeof(*result_arg));
    }
    memcpy(before,storage,capacity);
    int events=f.count, allocations=f.allocations, frees=f.frees;
    REQUIRE(bh_v2_transaction_observe_leaf_digests(owner_arg,claim_arg,result_arg) == BH_TX_REJECTED);
    REQUIRE(f.blocks[slot].alive && !memcmp(storage,before,capacity));
    REQUIRE(owner && f.count == events && f.allocations == allocations && f.frees == frees &&
            leaf_probe.hash_calls == 0 && leaf_probe.calls == 0);
    if (f.blocks[slot].alive) memcpy(storage,original,capacity);
    free(before); free(original);
    if (f.blocks[slot].alive)
        REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_nonzero_result(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    if (which == 0) result.status=99;
    else if (which == 1) result.ready=99;
    else if (which == 2) result.pair=99;
    else result.pid=99;
    struct bh_tx_result before=result;
    int events=f.count, allocations=f.allocations, frees=f.frees;
    REQUIRE(bh_v2_transaction_observe_leaf_digests(&owner,&claim,&result) == BH_TX_REJECTED);
    REQUIRE(!memcmp(&result,&before,sizeof(result)) && owner &&
            f.count == events && f.allocations == allocations && f.frees == frees &&
            leaf_probe.hash_calls == 0 && leaf_probe.calls == 0);
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_prerequisite_missing(int which) {
    int ok=1;
    leaf_config_default(); leaf_config.stop_after=which+1;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    int events=f.count, allocations=f.allocations, frees=f.frees, live=f.alloc_live;
    memset(&result,0,sizeof(result));
    uint32_t got=bh_v2_transaction_observe_leaf_digests(&owner,&claim,&result);
    REQUIRE(got == BH_TX_REJECTED && result.status == got && safe_result(&result));
    REQUIRE(owner && f.count == events && f.allocations == allocations &&
            f.frees == frees && f.alloc_live == live && !leaf_probe.hash_calls &&
            !leaf_probe.calls && !leaf_probe.errors && !f.errors);
    if (which == 0) {
        memset(&result,0,sizeof(result));
        REQUIRE(observe_call(&owner,&result) == BH_TX_PREPARED_UNTRUSTED &&
                result.status == BH_TX_PREPARED_UNTRUSTED &&
                original_leaf_reads() && f.alloc_live == 4);
    }
    if (which < 2) {
        memset(&result,0,sizeof(result));
        REQUIRE(local_state_call(&owner,&result) == BH_TX_PREPARED_UNTRUSTED &&
                result.status == BH_TX_PREPARED_UNTRUSTED &&
                state_original_reads() && state_full_trace() && f.alloc_live == 6);
    }
    REQUIRE(leaf_complete_startup(fixture,&owner,&result,&parameters));
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_prior_observation_failed(int which) {
    int ok=1;
    leaf_config_default(); leaf_config.stop_after=which+1;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    memset(&result,0,sizeof(result));
    if (which == 0) {
        f.pread_leaf=0; f.pread_pass=0; f.pread_kind=3;
        REQUIRE(observe_call(&owner,&result) == BH_TX_UNAVAILABLE &&
                f.pread_fault_reached == 1 && f.alloc_live == 1);
    } else if (which == 1) {
        f.state_pread_file=0; f.state_pread_pass=0; f.state_pread_kind=3;
        REQUIRE(local_state_call(&owner,&result) == BH_TX_UNAVAILABLE &&
                f.state_pread_fault_reached == 1 && f.alloc_live == 1);
    } else {
        bh_journal_parameters invalid={0};
        REQUIRE(codec_call(&owner,&invalid,&result) == BH_TX_REJECTED &&
                !codec_spy.calls && state_all_buffers_freed() && f.alloc_live == 1);
    }
    REQUIRE(result.status == (which == 2 ? BH_TX_REJECTED : BH_TX_UNAVAILABLE) &&
            safe_result(&result) && !f.errors);
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    int events=f.count, allocations=f.allocations, frees=f.frees;
    memset(&result,0,sizeof(result));
    REQUIRE(bh_v2_transaction_observe_leaf_digests(&owner,&claim,&result) == BH_TX_UNAVAILABLE);
    REQUIRE(result.status == BH_TX_UNAVAILABLE && safe_result(&result) &&
            f.count == events && f.allocations == allocations && f.frees == frees &&
            f.alloc_live == 1 && !leaf_probe.hash_calls && !leaf_probe.calls &&
            !leaf_probe.errors && !f.errors);
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_terminal_or_aborted(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    if (which == 0) { f.fail_at=f.count+6; f.failure_errno=EIO; }
    memset(&result,0,sizeof(result));
    uint32_t aborted=bh_v2_transaction_abort(&owner,&result);
    REQUIRE(aborted == (which == 0 ? BH_TX_UNAVAILABLE : BH_TX_ABORTED));
    REQUIRE(which == 0 ? owner != NULL : owner == NULL);
    int events=f.count, allocations=f.allocations, frees=f.frees;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    memset(&result,0,sizeof(result));
    uint32_t got=bh_v2_transaction_observe_leaf_digests(&owner,&claim,&result);
    REQUIRE(got == (which == 0 ? BH_TX_UNAVAILABLE : BH_TX_REJECTED));
    REQUIRE(result.status == (which == 0 ? BH_TX_UNAVAILABLE : 0u) &&
            safe_result(&result) && f.count == events && f.allocations == allocations &&
            f.frees == frees && leaf_probe.hash_calls == 0 && leaf_probe.calls == 0);
    REQUIRE(!f.alloc_live && borrowed_preserved());
    return ok;
}

static int leaf_repeat_after_outcome(int which) {
    int ok=1;
    leaf_config_default();
    if (which == 1) { leaf_config.mutate_leaf=0; leaf_config.mutate_at=0; }
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    if (which == 1) leaf_probe.spy_outcome=BH_JOURNAL_OFF_REJECT;
    if (which == 2) { leaf_probe.hash_fault_at=1; leaf_probe.hash_fault_kind=1; }
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    uint32_t first=which == 0 ? BH_TX_PREPARED_UNTRUSTED :
        which == 1 ? BH_TX_REJECTED : BH_TX_UNAVAILABLE;
    REQUIRE(leaf_expect(&owner,&claim,&result,first,which == 2 ? 1u : 2u,
        which == 2 ? 0u : 1u,which != 0));
    int events=f.count, frees=f.frees, allocations=f.allocations;
    unsigned hashes=leaf_probe.hash_calls, candidate=leaf_probe.calls;
    memset(&result,0,sizeof(result));
    uint32_t repeated=bh_v2_transaction_observe_leaf_digests(&owner,&claim,&result);
    uint32_t want=which == 0 ? BH_TX_REJECTED : BH_TX_UNAVAILABLE;
    REQUIRE(repeated == want && result.status == want && safe_result(&result));
    REQUIRE(f.count == events && f.frees == frees && f.allocations == allocations &&
            leaf_probe.hash_calls == hashes && leaf_probe.calls == candidate);
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_failure_latches_other_observation(int which) {
    int ok=1;
    leaf_config_default(); leaf_config.mutate_leaf=0; leaf_config.mutate_at=0;
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    leaf_probe.spy_outcome=BH_JOURNAL_OFF_REJECT;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_REJECTED,2,1,1));
    int events=f.count, frees=f.frees, allocations=f.allocations;
    unsigned hashes=leaf_probe.hash_calls, candidate=leaf_probe.calls;
    memset(&result,0,sizeof(result));
    uint32_t got=which == 0 ? observe_call(&owner,&result) :
        which == 1 ? local_state_call(&owner,&result) : codec_call(&owner,&parameters,&result);
    REQUIRE(got == BH_TX_UNAVAILABLE && result.status == BH_TX_UNAVAILABLE && safe_result(&result));
    REQUIRE(f.count == events && f.frees == frees && f.allocations == allocations &&
            leaf_probe.hash_calls == hashes && leaf_probe.calls == candidate &&
            codec_spy.calls == 1);
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_abort_after_outcome(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    if (which == 1) claim.epoch=0;
    if (which == 2) { leaf_probe.hash_fault_at=1; leaf_probe.hash_fault_kind=1; }
    uint32_t want=which == 0 ? BH_TX_PREPARED_UNTRUSTED :
        which == 1 ? BH_TX_REJECTED : BH_TX_UNAVAILABLE;
    REQUIRE(leaf_expect(&owner,&claim,&result,want,which == 0 ? 2u : which == 1 ? 0u : 1u,
        which == 0 ? 1u : 0u,which != 0));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_abort_ambiguous(int which) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
    f.cleanup_mode=1; f.failure_errno=EIO;
    f.fail_at=f.count+(which == 0 ? 6 : 5+owned_live());
    memset(&result,0,sizeof(result));
    uint32_t aborted=bh_v2_transaction_abort(&owner,&result);
    REQUIRE(aborted == BH_TX_UNAVAILABLE && result.status == aborted && safe_result(&result));
    REQUIRE(owner != NULL && f.fail_reached == 1 && f.quarantine_required &&
            !f.alloc_live && borrowed_preserved());
    int events=f.count, frees=f.frees, allocations=f.allocations;
    memset(&result,0,sizeof(result));
    REQUIRE(bh_v2_transaction_abort(&owner,&result) == BH_TX_UNAVAILABLE);
    REQUIRE(result.status == BH_TX_UNAVAILABLE && f.count == events && f.frees == frees &&
            f.allocations == allocations && owner != NULL);
    return ok;
}

static int leaf_codec_capture_explicit(void) {
    int ok=1;
    leaf_config_default();
    struct bh_v2_transaction *owner=NULL;
    struct bh_tx_result result={0}; bh_journal_parameters parameters;
    const struct leaf_fixture_data *fixture=&leaf_fixture_vectors[0];
    if (!leaf_prepare(fixture,&owner,&result,&parameters)) return 0;
    struct bh_tx_leaf_claim claim={fixture->epoch,fixture->key_state};
    REQUIRE(leaf_expect(&owner,&claim,&result,BH_TX_PREPARED_UNTRUSTED,2,1,0));
    REQUIRE(leaf_probe.candidate.epoch == fixture->epoch &&
            leaf_probe.candidate.key_state == fixture->key_state &&
            !memcmp(leaf_probe.candidate.policy_digest,fixture->policy_digest,32) &&
            !memcmp(leaf_probe.candidate.manifest_digest,fixture->manifest_digest,32));
    REQUIRE(leaf_finish(&owner,&result));
    return ok;
}

static int leaf_registry_valid(const struct leaf_case_data *rows, size_t count) {
    unsigned variants=0;
    if (count != BH_TX_LEAF_CASE_COUNT) return 0;
    for (size_t i=0; i<count; ++i) {
        if (!rows[i].name || !rows[i].variants) return 0;
        variants += rows[i].variants;
        for (size_t j=0; j<i; ++j)
            if (!strcmp(rows[i].name,rows[j].name)) return 0;
    }
    return variants == BH_TX_LEAF_VARIANTS_PER_LINK;
}

static int leaf_harness_self_gate(int which) {
    int ok=1;
    if (which < 2) {
        struct leaf_case_data damaged[BH_TX_LEAF_CASE_COUNT];
        memcpy(damaged,leaf_case_registry,sizeof(damaged));
        if (which == 0) REQUIRE(!leaf_registry_valid(damaged,BH_TX_LEAF_CASE_COUNT-1));
        else {
            damaged[1].name=damaged[0].name;
            REQUIRE(!leaf_registry_valid(damaged,BH_TX_LEAF_CASE_COUNT));
        }
    } else {
        REQUIRE(leaf_changed_leaf(0,0,BH_TX_REJECTED,BH_JOURNAL_OFF_REJECT));
        REQUIRE(leaf_probe.calls == 1 &&
                leaf_probe.observed_outcome == BH_JOURNAL_OFF_REJECT);
        /* Reuse the normal oracle with a wrong expectation while the observed
         * fake codec outcome remains OFF_REJECT. */
        int reversed_accepted=leaf_codec_outcome_matches(leaf_probe.observed_outcome,
                                                         BH_JOURNAL_CONSISTENT_ONLY);
        printf("LEAF ORACLE CONTROL observed=%d deliberately_expected=%d accepted=%d\n",
            (int)leaf_probe.observed_outcome,(int)BH_JOURNAL_CONSISTENT_ONLY,
            reversed_accepted);
        REQUIRE(!reversed_accepted);
    }
    return ok;
}

static int leaf_case_run(size_t group, int index) {
    if (group == 0) return leaf_structural_null(index);
    if (group == 1) return leaf_structural_public_overlap(index);
    if (group == 2) return leaf_private_alias(index,0);
    if (group == 3) return leaf_private_alias(index,1);
    if (group == 4) return leaf_nonzero_result(index);
    if (group == 5) return leaf_prerequisite_missing(index);
    if (group == 6) return leaf_prior_observation_failed(index);
    if (group == 7) return leaf_terminal_or_aborted(index);
    if (group == 8) return leaf_standard_positive(index);
    if (group == 9) return leaf_standard_positive(index+3);
    if (group == 10) return leaf_changed_leaf(0,index == 0 ? 0u :
        index == 1 ? leaf_fixture_vectors[0].policy_length/2 :
        leaf_fixture_vectors[0].policy_length-1,BH_TX_REJECTED,BH_JOURNAL_OFF_REJECT);
    if (group == 11) return leaf_changed_leaf(2,index == 0 ? 0u :
        index == 1 ? leaf_fixture_vectors[0].manifest_length/2 :
        leaf_fixture_vectors[0].manifest_length-1,BH_TX_REJECTED,BH_JOURNAL_OFF_REJECT);
    if (group == 12) return leaf_change_after_nul(index);
    if (group == 13) return leaf_caller_adjacent_digest(index);
    if (group == 14) return leaf_backing_change_after_capture(index);
    if (group == 15) return leaf_changed_leaf(1,3u,BH_TX_PREPARED_UNTRUSTED,
        BH_JOURNAL_CONSISTENT_ONLY);
    if (group == 16) return leaf_claim_invalid(index);
    if (group == 17) return leaf_claim_mismatch(index);
    if (group == 18) return leaf_invalid_version(index);
    if (group == 19) return leaf_valid_version_path(index);
    if (group == 20) return leaf_copied_install();
    if (group == 21) return leaf_version_mismatch(index);
    if (group == 22) return leaf_startup_parameter_copy(index);
    if (group == 23) return leaf_claim_entry_copy(index);
    if (group == 24) return leaf_hash_fault(index/2,index%2 ? 2 : 1,
        BH_TX_UNAVAILABLE,(unsigned)(index/2+1),0);
    if (group == 25) return leaf_hash_fault(index,3,BH_TX_UNAVAILABLE,(unsigned)(index+1),0);
    if (group == 26) return leaf_hash_fault(index,4,BH_TX_REJECTED,2,1);
    if (group == 27) return leaf_broken_snapshot_invariant(index);
    if (group == 28) return leaf_codec_outcome(index);
    if (group == 29) return leaf_startup_nonconsistent(index,1);
    if (group == 30) return leaf_startup_nonconsistent(index,0);
    if (group == 31) return leaf_repeat_after_outcome(index);
    if (group == 32) return leaf_failure_latches_other_observation(index);
    if (group == 33) return leaf_abort_after_outcome(index);
    if (group == 34) return leaf_abort_ambiguous(index);
    if (group == 35) return leaf_abort_after_outcome(index);
    if (group == 36) return leaf_codec_capture_explicit();
    if (group == 37) return leaf_harness_self_gate(index);
    fprintf(stderr,"UNIMPLEMENTED %s variant=%d\n",current,index);
    return 0;
}
#endif

int main(void) {
    unsigned variants=0;
    if (sizeof(leaf_case_registry)/sizeof(leaf_case_registry[0]) != BH_TX_LEAF_CASE_COUNT)
        return 2;
    for (size_t i=0; i<BH_TX_LEAF_CASE_COUNT; ++i) {
        if (!leaf_case_registry[i].name || !leaf_case_registry[i].variants) return 2;
        variants += leaf_case_registry[i].variants;
        for (size_t j=0; j<i; ++j)
            if (!strcmp(leaf_case_registry[i].name,leaf_case_registry[j].name)) return 2;
    }
    if (variants != BH_TX_LEAF_VARIANTS_PER_LINK ||
        strcmp(leaf_case_registry[8].name,"LeafDigest_WhenActiveTupleMatches_RemainsUntrusted") ||
        leaf_case_registry[8].variants != 3u) return 2;
    printf("LEAF REGISTRY unique=%u variants_per_link=%u links=2 planned=266\n",
        BH_TX_LEAF_CASE_COUNT,BH_TX_LEAF_VARIANTS_PER_LINK);
#ifdef BH_TX_LEAF_RED_STUB
    return leaf_positive_red();
#else
    unsigned executed=0, failed=0;
    for (size_t group=0; group<BH_TX_LEAF_CASE_COUNT; ++group) {
        current=leaf_case_registry[group].name;
        for (unsigned index=0; index<leaf_case_registry[group].variants; ++index) {
            variant=(int)index;
            ++executed;
            if (!leaf_case_run(group,(int)index)) ++failed;
        }
    }
    printf("LEAF DIGEST SUMMARY expected=%u executed=%u failed=%u skipped=0 unique=%u link=%s\n",
        BH_TX_LEAF_VARIANTS_PER_LINK,executed,failed,BH_TX_LEAF_CASE_COUNT,
#ifdef BH_TX_CODEC_SPY
        "spy");
#else
        "real");
#endif
    return failed || executed != BH_TX_LEAF_VARIANTS_PER_LINK;
#endif
}
