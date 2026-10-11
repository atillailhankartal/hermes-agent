#include "signed_preflight_v2_key_policy.h"
#include <CommonCrypto/CommonDigest.h>
#include <Security/Security.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { EXPECTED_CASES = 52, PCAP = 65585, MCAP = 65553 };
static const char *names[EXPECTED_CASES] = {
    "CheckKeyPolicy_WhenOldEpochBelowT_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenOldEpochAtTWithNewDigest_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenNewEpochTPlusOne_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenNewEpochUint64Max_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenTOneAndOldEpochOne_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenTMaxMinusOneAndNewMax_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenMinimumEqualsEpoch_ReturnsConsistentOnly",
    "CheckKeyPolicy_WhenOldValidSignatureAtTPlusOne_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenOldEpochUint64Max_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenNewEpochAtOrBelowT_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenTransitionEpochInvalid_DeniesConfig",
    "CheckKeyPolicy_WhenEntryCountNotTwo_DeniesConfig",
    "CheckKeyPolicy_WhenConfiguredIdMissing_DeniesConfig",
    "CheckKeyPolicy_WhenConfiguredIdsDuplicate_DeniesConfig",
    "CheckKeyPolicy_WhenEqualIdsHaveDifferentKeys_DeniesConfig",
    "CheckKeyPolicy_WhenConfiguredKeyDigestWrong_DeniesConfig",
    "CheckKeyPolicy_WhenConfiguredKeyShapeInvalid_DeniesConfig",
    "CheckKeyPolicy_WhenHeaderIdUnknown_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenHeaderIdMissing_DeniesWire",
    "CheckKeyPolicy_WhenEpochOrMinimumZero_DeniesTlv",
    "CheckKeyPolicy_WhenMinimumGreaterThanEpoch_DeniesTlv",
    "CheckKeyPolicy_WhenInstallationMismatch_DeniesBeforeCrypto",
    "CheckKeyPolicy_WhenConfiguredInstallationZero_DeniesConfig",
    "CheckKeyPolicy_WhenPolicyInstallationZero_DeniesTlv",
    "CheckKeyPolicy_WhenTransitionDigestZeroAtT_DeniesTransition",
    "CheckKeyPolicy_WhenTransitionDigestWrongAtT_DeniesTransition",
    "CheckKeyPolicy_WhenOldOrdinaryPolicyRepeatsTransitionDigest_DeniesTransition",
    "CheckKeyPolicy_WhenNewPolicyCarriesTransitionDigest_DeniesTransition",
    "CheckKeyPolicy_WhenArgumentsNull_DeniesWithoutReading",
    "CheckKeyPolicy_WhenSpanLengthInvalid_DeniesWithoutReading",
    "CheckKeyPolicy_WhenVersionOrHeaderWrong_DeniesWire",
    "CheckKeyPolicy_WhenBodyBoundInvalid_DeniesWire",
    "CheckKeyPolicy_WhenTlvHeaderTruncated_DeniesTlv",
    "CheckKeyPolicy_WhenTlvValueTruncated_DeniesTlv",
    "CheckKeyPolicy_WhenTlvLengthWrong_DeniesTlv",
    "CheckKeyPolicy_WhenTagsMissingDuplicateUnknownOrReordered_DeniesTlv",
    "CheckKeyPolicy_WhenManifestMismatch_DeniesStructureBeforeCrypto",
    "CheckKeyPolicy_WhenSignedHostModeMissing_DeniesStructureBeforeCrypto",
    "CheckKeyPolicy_WhenValidInputsReachSpy_PassesExactOwnedSelectedBytes",
    "CheckKeyPolicy_WhenMultipleFaultsExist_PreservesPrecheckOrdering",
    "CheckKeyPolicy_WhenCallbackRejects_DeniesCrypto",
    "CheckKeyPolicy_WhenCallbackUnavailable_ReturnsUnavailable",
    "CheckKeyPolicy_WhenSignatureTampered_DeniesCrypto",
    "CheckKeyPolicy_WhenSelectedKeyOffCurve_DeniesCrypto",
    "CheckKeyPolicy_WhenOriginalInputsMutateInsideCallback_UsesOwnedSnapshot",
    "CheckKeyPolicy_WhenInputsShareBackingStorage_RemainsBounded",
    "CheckKeyPolicy_WhenAllocationFails_ReturnsUnavailableWithoutCrypto",
    "CheckKeyPolicy_WhenResultZeroInitialized_RemainsDenial",
    "CheckKeyPolicy_WhenCallsRepeat_HasNoImplicitFloorOrCache",
    "CheckKeyPolicy_WhenDifferentOldPoliciesAtT_AreLocallyConsistentOnly",
    "CheckKeyPolicy_WhenInputsAreUnaligned_DecodesBytesSafely",
    "CheckKeyPolicy_WhenLengthsAtMaximum_RemainsBounded",
};

struct fixture {
    struct bh_key_policy_test_config config;
    uint8_t policy[PCAP], manifest[MCAP], signature[64];
    size_t plen, mlen;
};
struct spy {
    const struct fixture *expected;
    const struct fixture *original;
    struct fixture *mutate;
    unsigned calls;
    bool exact, real;
    int selected;
    enum bh_v2_crypto_status status;
};
static void require(bool ok, const char *why) {
    if (!ok) { fprintf(stderr, "FIXTURE_ERROR %s\n", why); exit(2); }
}
static unsigned u16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static void put16(uint8_t *p, size_t n) {
    require(n <= 65535, "representable u16"); p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n;
}
static void put32(uint8_t *p, uint32_t n) {
    for (unsigned i = 0; i < 4; i++) p[3-i] = (uint8_t)(n >> (8*i));
}
static void put64(uint8_t *p, uint64_t n) {
    for (unsigned i = 0; i < 8; i++) p[7-i] = (uint8_t)(n >> (8*i));
}
static size_t field(const uint8_t *p, size_t len, size_t header, unsigned tag) {
    size_t off = header;
    while (off <= len && len-off >= 4) {
        size_t n = u16(p+off+2);
        require(n <= len-off-4, "fixture TLV");
        if (u16(p+off) == tag) return off+4;
        off += 4+n;
    }
    require(false, "fixture missing field"); return 0;
}
static size_t load(const char *dir, const char *name, uint8_t *p, size_t cap) {
    char path[1024]; int n = snprintf(path,sizeof(path),"%s/%s",dir,name);
    require(n>0 && (size_t)n<sizeof(path),"fixture path");
    FILE *f=fopen(path,"rb"); require(f!=NULL,"fixture open");
    size_t len=fread(p,1,cap,f); require(!ferror(f) && feof(f),"fixture bounded read");
    require(fclose(f)==0,"fixture close"); return len;
}
static void hash(const uint8_t *p,size_t len,uint8_t out[32]) {
    require(len <= PCAP+64 && CC_SHA256(p,(CC_LONG)len,out)!=NULL,"sha256");
}
static SecKeyRef make_key(struct bh_key_policy_entry *entry) {
    int bits=256;
    CFNumberRef number=CFNumberCreate(NULL,kCFNumberIntType,&bits);
    const void *keys[]={kSecAttrKeyType,kSecAttrKeySizeInBits,kSecAttrIsPermanent};
    const void *values[]={kSecAttrKeyTypeECSECPrimeRandom,number,kCFBooleanFalse};
    CFDictionaryRef attrs=CFDictionaryCreate(NULL,keys,values,3,
        &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFErrorRef error=NULL;
    SecKeyRef key=SecKeyCreateRandomKey(attrs,&error);
    require(key!=NULL && error==NULL,"ephemeral key generation");
    SecKeyRef pub=SecKeyCopyPublicKey(key);
    CFDataRef data=SecKeyCopyExternalRepresentation(pub,&error);
    require(data!=NULL && error==NULL && CFDataGetLength(data)==65,"public export");
    memcpy(entry->public_key,CFDataGetBytePtr(data),65); entry->public_key_len=65;
    hash(entry->public_key,65,entry->id);
    CFRelease(data); CFRelease(pub); CFRelease(attrs); CFRelease(number);
    return key; /* Never export private representation, persist, or log it. */
}
static void sign_pair(struct fixture *f,SecKeyRef key) {
    static const uint8_t domain[]="BeeHermes.OperatorPolicy.v2";
    static const uint8_t order[32]={
        255,255,255,255,0,0,0,0,255,255,255,255,255,255,255,255,
        188,230,250,173,167,23,158,132,243,185,202,194,252,99,37,81};
    uint8_t preimage[PCAP+sizeof(domain)],digest[32],half[32];
    memcpy(preimage,domain,sizeof(domain)); memcpy(preimage+sizeof(domain),f->policy,f->plen);
    hash(preimage,sizeof(domain)+f->plen,digest);
    CFDataRef data=CFDataCreate(NULL,digest,32); CFErrorRef error=NULL;
    CFDataRef sig=SecKeyCreateSignature(key,kSecKeyAlgorithmECDSASignatureDigestX962SHA256,data,&error);
    require(sig!=NULL && error==NULL,"native signing");
    const uint8_t *der=CFDataGetBytePtr(sig); size_t dn=(size_t)CFDataGetLength(sig),pos=2;
    require(dn>=8 && dn<=72 && der[0]==0x30 && der[1]==dn-2,"DER sequence");
    memset(f->signature,0,64);
    for(unsigned i=0;i<2;i++) {
        require(pos+2<=dn && der[pos]==2,"DER integer"); size_t count=der[pos+1];pos+=2;
        require(count>=1 && count<=33 && count<=dn-pos,"DER bounded integer");
        if(count==33) {require(der[pos]==0,"DER padding");pos++;count--;}
        memcpy(f->signature+32*i+32-count,der+pos,count);pos+=count;
    }
    require(pos==dn,"DER end");
    unsigned carry=0;
    for (unsigned i=0;i<32;i++) { half[i]=(uint8_t)((order[i]>>1)|carry); carry=(order[i]&1)?128:0; }
    if (memcmp(f->signature+32,half,32)>0) {
        unsigned borrow=0;
        for (unsigned i=32;i>0;i--) {
            unsigned sub=(unsigned)f->signature[31+i]+borrow;
            f->signature[31+i]=(uint8_t)((unsigned)order[i-1]-sub);
            borrow=order[i-1]<sub;
        }
    }
    CFRelease(sig); CFRelease(data);
}
static void rebind(struct fixture *f) {
    hash(f->manifest,f->mlen,f->policy+field(f->policy,f->plen,48,3));
}
static void pair(struct fixture *f,const struct fixture *base,int slot,uint64_t epoch,uint64_t minimum) {
    *f=*base;
    memcpy(f->policy+16,f->config.entries[slot].id,32);
    put64(f->policy+52,epoch); put64(f->policy+64,minimum);
    uint8_t *next=f->policy+field(f->policy,f->plen,48,13);
    memset(next,0,32);
    if (slot==0 && epoch==f->config.transition_epoch) memcpy(next,f->config.entries[1].id,32);
}
static struct bh_v2_crypto_result verify(void *ctx,const uint8_t *p,size_t pn,
    const uint8_t *m,size_t mn,const uint8_t *s,size_t sn,const uint8_t *k,size_t kn) {
    struct spy *spy=ctx; const struct fixture *f=spy->expected;
    spy->calls++;
    spy->exact = spy->exact && pn==f->plen && mn==f->mlen && sn==64 && kn==65
        && p!=spy->original->policy && m!=spy->original->manifest && s!=spy->original->signature
        && k!=spy->original->config.entries[spy->selected].public_key
        && memcmp(p,f->policy,pn)==0 && memcmp(m,f->manifest,mn)==0
        && memcmp(s,f->signature,64)==0
        && memcmp(k,f->config.entries[spy->selected].public_key,65)==0;
    if (spy->mutate!=NULL) memset(spy->mutate,0,sizeof(*spy->mutate));
    if (spy->real) return bh_v2_check_signed_pair(p,pn,m,mn,s,sn,k,kn);
    return (struct bh_v2_crypto_result){spy->status,BH_V2_DENY_ARGUMENT};
}
static void control(const struct fixture *f,int slot,const char *label) {
    struct bh_v2_crypto_result r=bh_v2_check_signed_pair(f->policy,f->plen,f->manifest,f->mlen,
        f->signature,64,f->config.entries[slot].public_key,65);
    printf("CONTROL %s actual=%d expected=%d\n",label,r.status,BH_V2_CRYPTO_VALID_ONLY);
    require(r.status==BH_V2_CRYPTO_VALID_ONLY,"real crypto positive control");
}
static unsigned variants(unsigned n) {
    switch(n) {
    case 10:return 3; case 11:return 2; case 12:return 4;
    case 13:case 16:case 19:case 20:case 21:case 26:case 28:case 39:case 46:case 50:return 2;
    case 17:return 10; case 29:return 5; case 30:return 12; case 31:return 6;
    case 32:return 6; case 33:return 39; case 34:return 26; case 35:return 12;
    case 36:return 42; case 40:return 4; case 41:return 8; case 47:return 4; case 49:return 3;
    default:return 1;
    }
}
static void parameter_label(unsigned n,unsigned v,char label[96]) {
    (void)snprintf(label,96,"default");
    switch(n) {
    case 10:(void)snprintf(label,96,"new_epoch=%u",(unsigned[]){1,6,7}[v]);break;
    case 11:(void)snprintf(label,96,"transition=%s",v?"UINT64_MAX":"0");break;
    case 12:(void)snprintf(label,96,"entry_count=%s",(const char *[]){"0","1","3","SIZE_MAX"}[v]);break;
    case 13:case 16:(void)snprintf(label,96,"slot=%u",v);break;
    case 17:(void)snprintf(label,96,"slot=%u,shape=%s",v/5,(const char *[]){"len0","len64","len66","lenSIZE_MAX","prefix03"}[v%5]);break;
    case 19:(void)snprintf(label,96,"header=%s",v?"truncated47":"zero_id");break;
    case 20:(void)snprintf(label,96,"zero=%s",v?"minimum":"epoch");break;
    case 21:(void)snprintf(label,96,"minimum_gt_epoch=%s",v?"max":"7_gt_6");break;
    case 26:(void)snprintf(label,96,"next=%s",v?"third":"old");break;
    case 28:(void)snprintf(label,96,"new_epoch=%s",v?"UINT64_MAX":"8");break;
    case 29:(void)snprintf(label,96,"null=%s",(const char *[]){"config","policy","manifest","signature","callback"}[v]);break;
    case 30:(void)snprintf(label,96,"span=%s,length=%s",v<4?"policy":v<8?"manifest":"signature",
        (const char *[]){"0","48","65585","SIZE_MAX","0","16","65553","SIZE_MAX","0","63","65","SIZE_MAX"}[v]);break;
    case 31:(void)snprintf(label,96,"wire=%s",(const char *[]){"v1magic","v1version","header47","header49","magic6","magic7"}[v]);break;
    case 32:(void)snprintf(label,96,"body=%s",(const char *[]){"0","65537","UINT32_MAX","minus1","plus1","suffix"}[v]);break;
    case 33:(void)snprintf(label,96,"tag=%u,remaining=%u",v/3+1,v%3+1);break;
    case 34:(void)snprintf(label,96,"tag=%u,length=%s",v/2+1,v%2?"65535":"remaining_plus1");break;
    case 35:(void)snprintf(label,96,"tag=%u,length=%s",(unsigned[]){1,2,4,13}[v/3],
        v%3==0?"0":v/3<2?(v%3==1?"7":"9"):(v%3==1?"31":"33"));break;
    case 36:(void)snprintf(label,96,"mutation=%s,index=%u",v<13?"remove":v<26?"duplicate":v<29?"unknown":v<41?"adjacent_swap":"repeat13",v<26?v%13+1:v<29?(unsigned[]){0,14,65535}[v-26]:v<41?v-28:13);break;
    case 39:(void)snprintf(label,96,"selected=%s",v?"new":"old");break;
    case 40:(void)snprintf(label,96,"first=%s",(const char *[]){"config","key_id","epoch","installation"}[v]);break;
    case 41:(void)snprintf(label,96,"crypto_status=%u",(unsigned[]){0,2,3,4,5,6,7,999}[v]);break;
    case 46:(void)snprintf(label,96,"alias=%s",v?"partial_policy_manifest_signature":"signature_inside_policy");break;
    case 47:(void)snprintf(label,96,"fault=%s,ordinal=%u",v<2?"allocation":"sha",v%2+1);break;
    case 49:(void)snprintf(label,96,"sequence_index=%u,key=%s",v,v==1?"new":"old");break;
    case 50:(void)snprintf(label,96,"at_T_minimum=%u",v+1);break;
    default:break;
    }
}
static bool run_variant(const char *dir,const struct fixture *base,SecKeyRef keys[3],
                        unsigned n,unsigned v) {
    struct fixture f; pair(&f,base,0,6,1);
    enum bh_key_policy_status want=BH_KEY_POLICY_CONSISTENT_ONLY;
    unsigned calls=1, fail_alloc=0, fail_sha=0;
    int slot=0;
    const struct bh_key_policy_test_config *cfg=&f.config;
    const uint8_t *p=f.policy,*m=f.manifest,*s=f.signature;
    size_t pn=f.plen,mn=f.mlen,sn=64;
    bh_key_policy_test_verify_fn callback=verify;
    struct spy spy={&f,&f,NULL,0,true,false,0,BH_V2_CRYPTO_VALID_ONLY};
    bool signing=false, direct=false;
    size_t off=0,len=0;
    if (n>=8 && n<=38) calls=0;
    switch(n) {
    case 1: signing=true; break;
    case 2: pair(&f,base,0,7,1); signing=true; break;
    case 3: slot=1; pair(&f,base,1,8,1); signing=true; break;
    case 4: slot=1; pair(&f,base,1,UINT64_MAX,UINT64_MAX); signing=true; break;
    case 5: f.config.transition_epoch=1; put64(f.policy+52,1);
        memcpy(f.policy+field(f.policy,f.plen,48,13),f.config.entries[1].id,32); signing=true; break;
    case 6: slot=1; pair(&f,base,1,UINT64_MAX,1); f.config.transition_epoch=UINT64_MAX-1; signing=true; break;
    case 7: put64(f.policy+64,6); signing=true; break;
    case 8: put64(f.policy+52,8); signing=true; direct=true; want=BH_KEY_POLICY_DENY_EPOCH; break;
    case 9: put64(f.policy+52,UINT64_MAX); want=BH_KEY_POLICY_DENY_EPOCH; break;
    case 10: slot=1; pair(&f,base,1,(uint64_t[]){1,6,7}[v],1); want=BH_KEY_POLICY_DENY_EPOCH; break;
    case 11: f.config.transition_epoch=v?UINT64_MAX:0; want=BH_KEY_POLICY_DENY_CONFIG; break;
    case 12: f.config.entry_count=(size_t[]){0,1,3,SIZE_MAX}[v]; want=BH_KEY_POLICY_DENY_CONFIG; break;
    case 13: memset(f.config.entries[v].id,0,32); want=BH_KEY_POLICY_DENY_CONFIG; break;
    case 14: f.config.entries[1]=f.config.entries[0]; want=BH_KEY_POLICY_DENY_CONFIG; break;
    case 15: memcpy(f.config.entries[1].id,f.config.entries[0].id,32); want=BH_KEY_POLICY_DENY_CONFIG; break;
    case 16: f.config.entries[v].id[0]^=1; want=BH_KEY_POLICY_DENY_CONFIG; break;
    case 17:
        if(v%5==4) f.config.entries[v/5].public_key[0]=3;
        else f.config.entries[v/5].public_key_len=(size_t[]){0,64,66,SIZE_MAX}[v%5];
        want=BH_KEY_POLICY_DENY_CONFIG; break;
    case 18: {
        struct bh_key_policy_entry third;
        SecKeyRef pub=SecKeyCopyPublicKey(keys[2]); CFErrorRef error=NULL;
        CFDataRef data=SecKeyCopyExternalRepresentation(pub,&error);
        require(data!=NULL && error==NULL && CFDataGetLength(data)==65,"third public");
        memcpy(third.public_key,CFDataGetBytePtr(data),65); third.public_key_len=65;
        hash(third.public_key,65,third.id); memcpy(f.policy+16,third.id,32);
        sign_pair(&f,keys[2]);
        struct bh_v2_crypto_result r=bh_v2_check_signed_pair(f.policy,f.plen,f.manifest,f.mlen,
            f.signature,64,third.public_key,65);
        printf("CONTROL unknown-id actual=%d expected=%d\n",r.status,BH_V2_CRYPTO_VALID_ONLY);
        require(r.status==BH_V2_CRYPTO_VALID_ONLY,"unknown signed control");
        CFRelease(data); CFRelease(pub); want=BH_KEY_POLICY_DENY_KEY_ID; break;
    }
    case 19:
        if(v) {pn=47;want=BH_KEY_POLICY_DENY_ARGUMENT;}
        else {memset(f.policy+16,0,32);want=BH_KEY_POLICY_DENY_POLICY_WIRE;} break;
    case 20: put64(f.policy+(v?64:52),0); want=BH_KEY_POLICY_DENY_POLICY_TLV; break;
    case 21: put64(f.policy+52,v?UINT64_MAX-1:6); put64(f.policy+64,v?UINT64_MAX:7);
        want=BH_KEY_POLICY_DENY_POLICY_TLV; break;
    case 22: f.policy[field(f.policy,f.plen,48,4)]^=1;
        f.manifest[field(f.manifest,f.mlen,16,1)]^=1; rebind(&f);
        signing=true; direct=true; want=BH_KEY_POLICY_DENY_INSTALLATION; break;
    case 23: memset(f.config.installation_digest,0,32); want=BH_KEY_POLICY_DENY_CONFIG; break;
    case 24: memset(f.policy+field(f.policy,f.plen,48,4),0,32); want=BH_KEY_POLICY_DENY_POLICY_TLV; break;
    case 25: put64(f.policy+52,7); want=BH_KEY_POLICY_DENY_TRANSITION; break;
    case 26: put64(f.policy+52,7); off=field(f.policy,f.plen,48,13);
        memcpy(f.policy+off,f.config.entries[0].id,32); if(v) f.policy[off]^=1;
        want=BH_KEY_POLICY_DENY_TRANSITION; break;
    case 27: memcpy(f.policy+field(f.policy,f.plen,48,13),f.config.entries[1].id,32);
        want=BH_KEY_POLICY_DENY_TRANSITION; break;
    case 28: slot=1; pair(&f,base,1,v?UINT64_MAX:8,1);
        memcpy(f.policy+field(f.policy,f.plen,48,13),f.config.entries[1].id,32);
        want=BH_KEY_POLICY_DENY_TRANSITION; break;
    case 29: if(v==0)cfg=NULL; if(v==1)p=NULL; if(v==2)m=NULL; if(v==3)s=NULL; if(v==4)callback=NULL;
        want=BH_KEY_POLICY_DENY_ARGUMENT; break;
    case 30:
        if(v<4)pn=(size_t[]){0,48,65585,SIZE_MAX}[v];
        else if(v<8)mn=(size_t[]){0,16,65553,SIZE_MAX}[v-4];
        else sn=(size_t[]){0,63,65,SIZE_MAX}[v-8];
        want=BH_KEY_POLICY_DENY_ARGUMENT; break;
    case 31:
        if(v==0) f.policy[5]='1'; if(v==1)put16(f.policy+8,1);
        if(v==2 || v==3)put16(f.policy+10,v==2?47:49);
        if(v==4 || v==5)f.policy[v==4?6:7]=1;
        want=BH_KEY_POLICY_DENY_POLICY_WIRE; break;
    case 32:
        if(v<5)put32(f.policy+12,(uint32_t[]){0,65537,UINT32_MAX,(uint32_t)f.plen-49,(uint32_t)f.plen-47}[v]);
        else pn++; want=BH_KEY_POLICY_DENY_POLICY_WIRE; break;
    case 33:
        off=field(f.policy,f.plen,48,v/3+1)-4; pn=off+v%3+1;
        put32(f.policy+12,(uint32_t)pn-48); want=BH_KEY_POLICY_DENY_POLICY_TLV; break;
    case 34:
        off=field(f.policy,f.plen,48,v/2+1);
        put16(f.policy+off-2,v%2?65535:f.plen-off+1);
        want=BH_KEY_POLICY_DENY_POLICY_TLV; break;
    case 35: {
        unsigned tag=(unsigned[]){1,2,4,13}[v/3]; off=field(f.policy,f.plen,48,tag);
        put16(f.policy+off-2,(v%3==0)?0:(tag<=2?(v%3==1?7:9):(v%3==1?31:33)));
        want=BH_KEY_POLICY_DENY_POLICY_TLV; break;
    }
    case 36:
        if(v<26) {
            unsigned tag=v%13+1; off=field(f.policy,f.plen,48,tag)-4;len=4+u16(f.policy+off+2);
            if(v<13) {memmove(f.policy+off,f.policy+off+len,f.plen-off-len);f.plen-=len;}
            else {memmove(f.policy+off+len,f.policy+off,f.plen-off); f.plen+=len;}
        } else if(v<29) put16(f.policy+48,(unsigned[]){0,14,65535}[v-26]);
        else if(v<41) {
            unsigned tag=v-29+1;off=field(f.policy,f.plen,48,tag)-4;
            size_t second=field(f.policy,f.plen,48,tag+1)-4;
            put16(f.policy+off,tag+1);put16(f.policy+second,tag);
        } else {off=field(f.policy,f.plen,48,13)-4;len=f.plen-off;memcpy(f.policy+f.plen,f.policy+off,len);f.plen+=len;}
        pn=f.plen;put32(f.policy+12,(uint32_t)pn-48);want=BH_KEY_POLICY_DENY_POLICY_TLV;break;
    case 37:f.manifest[20]^=1;want=BH_KEY_POLICY_DENY_STRUCTURE;break;
    case 38:
        f.mlen=load(dir,"H-MISSING-manifest.bin",f.manifest,MCAP);mn=f.mlen;rebind(&f);
        want=BH_KEY_POLICY_DENY_STRUCTURE;break;
    case 39:slot=(int)v;pair(&f,base,slot,v?8:6,1);break;
    case 40:
        calls=0;
        if(v==0) {f.config.entry_count=0;f.policy[16]^=1;want=BH_KEY_POLICY_DENY_CONFIG;}
        if(v==1) {f.policy[16]^=1;put64(f.policy+52,8);want=BH_KEY_POLICY_DENY_KEY_ID;}
        if(v==2) {put64(f.policy+52,8);f.policy[112]^=1;want=BH_KEY_POLICY_DENY_EPOCH;}
        if(v==3) {f.policy[112]^=1;f.policy[field(f.policy,f.plen,48,13)]=1;want=BH_KEY_POLICY_DENY_INSTALLATION;}
        break;
    case 41:spy.status=(enum bh_v2_crypto_status[]){BH_V2_CRYPTO_DENY,BH_V2_CRYPTO_DENY_ARGUMENT,
        BH_V2_CRYPTO_DENY_POLICY_WIRE,BH_V2_CRYPTO_DENY_KEY,BH_V2_CRYPTO_DENY_SIGNATURE_FORMAT,
        BH_V2_CRYPTO_DENY_SIGNATURE,BH_V2_CRYPTO_DENY_STRUCTURE,(enum bh_v2_crypto_status)999}[v];
        want=BH_KEY_POLICY_DENY_CRYPTO;break;
    case 42:spy.status=BH_V2_CRYPTO_UNAVAILABLE;want=BH_KEY_POLICY_UNAVAILABLE;break;
    case 43:
        sign_pair(&f,keys[0]);f.signature[31]^=1;
        require(bh_v2_check_signed_pair(f.policy,f.plen,f.manifest,f.mlen,f.signature,64,
            f.config.entries[0].public_key,65).status==BH_V2_CRYPTO_DENY_SIGNATURE,"tamper canonical negative");
        spy.real=true;want=BH_KEY_POLICY_DENY_CRYPTO;break;
    case 44:sign_pair(&f,keys[0]);memset(f.config.entries[0].public_key+1,0,64);
        hash(f.config.entries[0].public_key,65,f.config.entries[0].id);
        memcpy(f.policy+16,f.config.entries[0].id,32);
        require(bh_v2_check_signed_pair(f.policy,f.plen,f.manifest,f.mlen,f.signature,64,
            f.config.entries[0].public_key,65).status==BH_V2_CRYPTO_DENY_KEY,"offcurve import negative");
        printf("CONTROL offcurve actual=4 expected=4\n");
        spy.real=true;want=BH_KEY_POLICY_DENY_CRYPTO;break;
    case 45:signing=true;spy.mutate=&f;break;
    case 46: s=f.policy+(v?20:0); if(v)m=f.policy+1; mn=v?f.plen-1:f.mlen;
        want=v?BH_KEY_POLICY_DENY_STRUCTURE:BH_KEY_POLICY_DENY_CRYPTO;calls=v?0:1;spy.real=true;break;
    case 47:
        if(v<2)fail_alloc=v+1;else fail_sha=v-1;
        want=BH_KEY_POLICY_UNAVAILABLE;calls=0;break;
    case 48:require((enum bh_key_policy_status){0}==BH_KEY_POLICY_DENY && BH_KEY_POLICY_DENY!=BH_KEY_POLICY_CONSISTENT_ONLY,"zero deny");break;
    case 49:slot=v==1?1:0;pair(&f,base,slot,v==1?8:6,1);signing=true;break;
    case 50:pair(&f,base,0,7,v?2:1);signing=true;break;
    case 51:signing=true;break;
    case 52:
        pn=65584;mn=65552;put32(f.policy+12,65536);put32(f.manifest+12,65536);
        want=BH_KEY_POLICY_DENY_POLICY_TLV;calls=0;break;
    default:require(false,"case number");
    }
    if(signing) {sign_pair(&f,keys[slot]);spy.real=true;}
    if(signing || direct)control(&f,slot,names[n-1]);
    spy.selected=slot;
    struct fixture expected=f;spy.expected=&expected;
    uint8_t original_digest[32],after_digest[32];
    require(CC_SHA256(&f,(CC_LONG)sizeof(f),original_digest)!=NULL,"original hash");
    uint8_t up[PCAP+1],um[MCAP+1],us[65];
    if(n==51) {memcpy(up+1,f.policy,pn);memcpy(um+1,f.manifest,mn);memcpy(us+1,f.signature,64);p=up+1;m=um+1;s=us+1;}
    if(n==46) {memcpy(expected.signature,s,64); if(v){memcpy(expected.manifest,m,mn);expected.mlen=mn;}}
    enum bh_key_policy_status actual;
#ifdef BH_KEY_POLICY_TESTING
    if(n==47) actual=bh_v2_key_policy_fault_test(cfg,p,pn,m,mn,s,sn,callback,&spy,fail_alloc,fail_sha);
    else
#endif
        actual=bh_v2_check_key_policy_for_test(cfg,p,pn,m,mn,s,sn,callback,&spy);
    (void)fail_alloc;(void)fail_sha;
    bool ok=actual==want && spy.calls==calls && (calls==0 || spy.exact);
    if(n==46) {
        struct spy reference={&expected,&expected,NULL,0,true,true,0,BH_V2_CRYPTO_VALID_ONLY};
        enum bh_key_policy_status separate=bh_v2_check_key_policy_for_test(&expected.config,
            expected.policy,pn,expected.manifest,mn,expected.signature,64,verify,&reference);
        ok=ok && actual==separate && reference.calls==calls && reference.exact;
    }
    if(n==45) {
        struct spy after={&f,&f,NULL,0,true,false,0,BH_V2_CRYPTO_VALID_ONLY};
        enum bh_key_policy_status again=bh_v2_check_key_policy_for_test(&f.config,f.policy,pn,f.manifest,mn,f.signature,64,verify,&after);
        ok=ok && again==BH_KEY_POLICY_DENY_CONFIG && after.calls==0;
    } else {
        require(CC_SHA256(&f,(CC_LONG)sizeof(f),after_digest)!=NULL,"after hash");
        ok=ok && memcmp(original_digest,after_digest,32)==0;
    }
    char label[96];parameter_label(n,v,label);
    printf("PARAM %s variant=%u label=%s actual=%d expected=%d calls=%u expected_calls=%u exact=%d %s\n",
        names[n-1],v,label,actual,want,spy.calls,calls,spy.exact,ok?"PASS":"FAIL");
    return ok;
}
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    struct fixture base={0};
    base.plen=load(argv[1],"S2-policy.bin",base.policy,PCAP);
    base.mlen=load(argv[1],"S2-manifest.bin",base.manifest,MCAP);
    base.config.entry_count=2;base.config.transition_epoch=7;
    memcpy(base.config.installation_digest,base.policy+field(base.policy,base.plen,48,4),32);
    struct bh_key_policy_entry third;
    SecKeyRef keys[3]={make_key(&base.config.entries[0]),make_key(&base.config.entries[1]),make_key(&third)};
    unsigned failures=0,parameters=0,param_failures=0;
    for(unsigned n=1;n<=EXPECTED_CASES;n++) {
        bool ok=true;
        for(unsigned v=0;v<variants(n);v++) {bool pass=run_variant(argv[1],&base,keys,n,v);parameters++;if(!pass)param_failures++;ok=pass&&ok;}
        printf("%s %s\n",ok?"PASS":"FAIL",names[n-1]);if(!ok)failures++;
    }
    for(unsigned i=0;i<3;i++)CFRelease(keys[i]);
    printf("key_policy cases=52 failures=%u parameters=%u parameter_failures=%u skips=0\n",failures,parameters,param_failures);
    return failures?1:0;
}
