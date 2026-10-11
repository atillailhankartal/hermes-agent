#include "signed_preflight_v2_key_policy.h"

#include <CommonCrypto/CommonDigest.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static bool nonzero(const uint8_t *p,size_t n) {
    uint8_t combined=0;
    for(size_t i=0;i<n;i++)combined|=p[i];
    return combined!=0;
}
static unsigned be16(const uint8_t *p) { return ((unsigned)p[0]<<8)|p[1]; }
static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static uint64_t be64(const uint8_t *p) {
    uint64_t value=0;
    for(unsigned i=0;i<8;i++)value=(value<<8)|p[i];
    return value;
}
struct fields { uint64_t epoch; uint8_t installation[32],next[32]; };
static bool policy_fields(const uint8_t *p,size_t n,struct fields *out) {
    size_t cursor=48;
    uint64_t minimum=0;
    for(unsigned tag=1;tag<=13;tag++) {
        if(cursor>n || n-cursor<4)return false;
        unsigned actual=be16(p+cursor),len=be16(p+cursor+2);
        if(actual!=tag || len==0)return false;
        cursor+=4;
        if(len>n-cursor)return false;
        if(tag==1 || tag==2) {
            if(len!=8)return false;
            uint64_t value=be64(p+cursor);
            if(value==0)return false;
            if(tag==1)out->epoch=value;else minimum=value;
        } else if(tag==4 || tag==13) {
            if(len!=32)return false;
            if(tag==4) {
                if(!nonzero(p+cursor,32))return false;
                memcpy(out->installation,p+cursor,32);
            } else memcpy(out->next,p+cursor,32);
        }
        cursor+=len;
    }
    return cursor==n && minimum<=out->epoch;
}
/* Injection ordinals are local values, never global allocator/SHA replacement.
 * The ordinary dormant API always supplies zero; only the separate test image
 * exposes the fault wrapper. Config/signature use fixed owned stack storage. */
static enum bh_key_policy_status check(
    const struct bh_key_policy_test_config *config,
    const uint8_t *policy,size_t policy_len,const uint8_t *manifest,size_t manifest_len,
    const uint8_t *signature,size_t signature_len,bh_key_policy_test_verify_fn verify,void *ctx,
    unsigned fail_allocation,unsigned fail_sha) {
    static const uint8_t magic[8]={'B','H','P','O','L','2',0,0};
    if(config==NULL || policy==NULL || manifest==NULL || signature==NULL || verify==NULL
        || policy_len<49 || policy_len>65584 || manifest_len<17 || manifest_len>65552
        || signature_len!=64)return BH_KEY_POLICY_DENY_ARGUMENT;
    enum bh_key_policy_status result=BH_KEY_POLICY_UNAVAILABLE;
    struct bh_key_policy_test_config owned_config;
    uint8_t owned_signature[64];
    uint8_t *p=fail_allocation==1?NULL:malloc(policy_len);
    uint8_t *m=fail_allocation==2?NULL:malloc(manifest_len);
    if(p==NULL || m==NULL)goto done;
    memcpy(&owned_config,config,sizeof(owned_config));
    memcpy(p,policy,policy_len);memcpy(m,manifest,manifest_len);
    memcpy(owned_signature,signature,64);
    /* Caller sources are never consulted after these copies. */
    const struct bh_key_policy_test_config *c=&owned_config;
    result=BH_KEY_POLICY_DENY_CONFIG;
    if(c->entry_count!=2 || c->transition_epoch==0 || c->transition_epoch==UINT64_MAX
        || !nonzero(c->installation_digest,32)
        || !nonzero(c->entries[0].id,32) || !nonzero(c->entries[1].id,32)
        || memcmp(c->entries[0].id,c->entries[1].id,32)==0)goto done;
    for(unsigned i=0;i<2;i++) {
        uint8_t digest[32];
        if(c->entries[i].public_key_len!=65 || c->entries[i].public_key[0]!=4)goto done;
        if(fail_sha==i+1 || CC_SHA256(c->entries[i].public_key,65,digest)==NULL) {
            result=BH_KEY_POLICY_UNAVAILABLE;goto done;
        }
        if(memcmp(digest,c->entries[i].id,32)!=0)goto done;
    }
    result=BH_KEY_POLICY_DENY_POLICY_WIRE;
    uint32_t body=be32(p+12);
    if(memcmp(p,magic,8)!=0 || be16(p+8)!=2 || be16(p+10)!=48
        || body==0 || body>65536 || policy_len-48!=body || !nonzero(p+16,32))goto done;
    struct fields fields={0};
    result=BH_KEY_POLICY_DENY_POLICY_TLV;
    if(!policy_fields(p,policy_len,&fields))goto done;
    unsigned selected;
    result=BH_KEY_POLICY_DENY_KEY_ID;
    if(memcmp(p+16,c->entries[0].id,32)==0)selected=0;
    else if(memcmp(p+16,c->entries[1].id,32)==0)selected=1;
    else goto done;
    result=BH_KEY_POLICY_DENY_EPOCH;
    if((selected==0 && fields.epoch>c->transition_epoch)
        || (selected==1 && fields.epoch<=c->transition_epoch))goto done;
    result=BH_KEY_POLICY_DENY_INSTALLATION;
    if(memcmp(fields.installation,c->installation_digest,32)!=0)goto done;
    result=BH_KEY_POLICY_DENY_TRANSITION;
    if(selected==0 && fields.epoch==c->transition_epoch) {
        if(memcmp(fields.next,c->entries[1].id,32)!=0)goto done;
    } else if(nonzero(fields.next,32))goto done;
    result=BH_KEY_POLICY_DENY_STRUCTURE;
    if(bh_v2_validate_structure(p,policy_len,m,manifest_len)!=BH_V2_STRUCTURE_ONLY)goto done;
    struct bh_v2_crypto_result crypto=verify(ctx,p,policy_len,m,manifest_len,
        owned_signature,64,c->entries[selected].public_key,65);
    if(crypto.status==BH_V2_CRYPTO_VALID_ONLY)result=BH_KEY_POLICY_CONSISTENT_ONLY;
    else if(crypto.status==BH_V2_CRYPTO_UNAVAILABLE)result=BH_KEY_POLICY_UNAVAILABLE;
    else result=BH_KEY_POLICY_DENY_CRYPTO;
done:
    free(m);free(p);return result;
}
enum bh_key_policy_status bh_v2_check_key_policy_for_test(
    const struct bh_key_policy_test_config *config,
    const uint8_t *policy,size_t policy_len,const uint8_t *manifest,size_t manifest_len,
    const uint8_t *signature,size_t signature_len,bh_key_policy_test_verify_fn verify,void *ctx) {
    return check(config,policy,policy_len,manifest,manifest_len,signature,signature_len,verify,ctx,0,0);
}
#ifdef BH_KEY_POLICY_TESTING
enum bh_key_policy_status bh_v2_key_policy_fault_test(
    const struct bh_key_policy_test_config *config,
    const uint8_t *policy,size_t policy_len,const uint8_t *manifest,size_t manifest_len,
    const uint8_t *signature,size_t signature_len,bh_key_policy_test_verify_fn verify,void *ctx,
    unsigned fail_allocation,unsigned fail_sha) {
    return check(config,policy,policy_len,manifest,manifest_len,signature,signature_len,
                 verify,ctx,fail_allocation,fail_sha);
}
#endif
