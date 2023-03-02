//#include <bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <netdutils/UidConstants.h>
#include "bpf_helpers.h"
//#include "bpf_net_helpers.h"
//#include "netdbpf/bpf_shared.h"
//#include "netdbpf/ss_bpf_shared.h"
#include <ss_bpf_shared.h>

//APE : start
#include <linux/pkt_cls.h>
#include <linux/filter.h>

// bionic kernel uapi linux/udp.h header is munged...
#define __kernel_udphdr udphdr
#include <linux/udp.h>
//APE : end

// This is used for xt_bpf program only.
#define BPF_NOMATCH 0
#define BPF_MATCH 1

#define IPV6_PROTO_OFF offsetof(struct ipv6hdr, nexthdr)

//APE : start
#define IP_OFF_SRC   (offsetof(struct iphdr, saddr))
#define IP_OFF_DST   (offsetof(struct iphdr, daddr))
#define IP_ETH_OFF_SRC   (ETH_HLEN + IP_OFF_SRC)
#define IP_ETH_OFF_DST   (ETH_HLEN + IP_OFF_DST)

#define TCP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))
#define TCP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))

#define UDP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest))
#define UDP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, source))
// > APE:End


DEFINE_BPF_MAP(oem_uid_owner_map, HASH, uint32_t, OemUidOwnerValue, OEM_UID_OWNER_MAP_SIZE)

// < APE:Start
#define SEMAPE_UID_DEST_MAP_SIZE 2048
DEFINE_BPF_MAP(ape_uid_dest_map, HASH, uint32_t, uint8_t, SEMAPE_UID_DEST_MAP_SIZE)
DEFINE_BPF_MAP(ape_uid_dest6_map, HASH, uint16_t, uint8_t, SEMAPE_UID_DEST_MAP_SIZE)
// > APE:End

static __always_inline int is_system_uid(uint32_t uid) {
    return (uid <= MAX_SYSTEM_UID) && (uid >= MIN_SYSTEM_UID);
}

// "bpf_net_helpers.h" removed. argg! re-invent the wheel.
static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to,
                                 int len) = (void*)BPF_FUNC_skb_load_bytes;

static uint32_t (*bpf_get_socket_uid)(struct __sk_buff* skb) = (void*)BPF_FUNC_get_socket_uid;

// Android only supports little endian architectures
#define htons(x) (__builtin_constant_p(x) ? ___constant_swab16(x) : __builtin_bswap16(x))
#define htonl(x) (__builtin_constant_p(x) ? ___constant_swab32(x) : __builtin_bswap32(x))
#define ntohs(x) htons(x)
#define ntohl(x) htonl(x)

//< APE : start
static inline bool ape_is_uid_allowed(struct __sk_buff* skb){

    uint32_t sock_uid = bpf_get_socket_uid(skb);
    if (is_system_uid(sock_uid)) return BPF_MATCH;

    OemUidOwnerValue *semApeMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
    if (semApeMatch)
        return semApeMatch->rule & SEMAPE_WLAN_MATCH;

    return BPF_NOMATCH;
}

static inline void ape_mark_uid_dest_map(struct __sk_buff* skb, int offset){
    __u32 key = ntohl(load_word(skb, offset));
    __u8 mark = 1;

    bpf_ape_uid_dest_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
}

static inline void ape_mark_uid_dest6_map(__u16 key){
    __u8 mark = 1;

    bpf_ape_uid_dest6_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
}

//SEC("schedcls/ingress/ape_ether")
DEFINE_BPF_PROG("schedcls/ingress/ape_ether", AID_ROOT, AID_SYSTEM, sched_cls_ingress_ape_ether)
(struct __sk_buff* skb) {

    if (skb->protocol == htons(ETH_P_IP)) {
        __u32 key = ntohl(load_word(skb, IP_ETH_OFF_SRC));
        __u8 *mark = bpf_ape_uid_dest_map_lookup_elem(&key);
        if (mark) {
            //skb->priority = 7;
            return TC_ACT_OK;
        }
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        int offset = ETH_HLEN + IPV6_PROTO_OFF;
        int ret = 0;
        uint8_t proto;
        ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
        if (!ret) {
            if (proto == IPPROTO_TCP) {
                __u16 key = load_half(skb, TCP6_DPORT_OFF);
                __u8 *mark = bpf_ape_uid_dest6_map_lookup_elem(&key);
                if (mark) {
                    //skb->priority = 7;
                    return TC_ACT_OK;
                }
            } else if (proto == IPPROTO_UDP) {
                __u16 key = load_half(skb, UDP6_DPORT_OFF);
                __u8 *mark = bpf_ape_uid_dest6_map_lookup_elem(&key);
                if (mark) {
                    //skb->priority = 7;
                    return TC_ACT_OK;
                }
            }
        }
    }
    skb->priority = 0;
    return TC_ACT_UNSPEC;
}

//SEC("schedcls/egress/ape_ether")
DEFINE_BPF_PROG("schedcls/egress/ape_ether", AID_ROOT, AID_SYSTEM, sched_cls_egress_ape_ether)
(struct __sk_buff* skb) {

    bool is_allowed =  ape_is_uid_allowed(skb);
    
    if (is_allowed) {
        if (skb->protocol == htons(ETH_P_IP)) {
            ape_mark_uid_dest_map(skb, IP_ETH_OFF_DST);
            //skb->priority = 7;
            return TC_ACT_OK;
        } else if (skb->protocol == htons(ETH_P_IPV6)) {
            int ret = 0;
            int offset = ETH_HLEN + IPV6_PROTO_OFF;
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
            if (!ret) {
                if (proto == IPPROTO_TCP) {
                    __u16 key = load_half(skb, TCP6_SPORT_OFF);
                    ape_mark_uid_dest6_map(key);
                    //skb->priority = 7;
                    return TC_ACT_OK;
                } else if (proto == IPPROTO_UDP) {
                    __u16 key = load_half(skb, UDP6_SPORT_OFF);
                    ape_mark_uid_dest6_map(key);
                    //skb->priority = 7;
                    return TC_ACT_OK;
                }
            }
        }
    }

    //skb->priority = 0;
    return TC_ACT_UNSPEC;
}
// > APE : end

// < GMS-CORE : start
DEFINE_BPF_PROG("skfilter/mobilefw/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_mobilefw_prog)
(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    OemUidOwnerValue* firewallMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
        if (firewallMatch) {
            return firewallMatch->rule 
                & FIREWALL_MOBILE_DATA_MATCH ? BPF_MATCH : BPF_NOMATCH;
        }
    return BPF_NOMATCH;
}

DEFINE_BPF_PROG("skfilter/wlanfw/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_wlanfw_prog)
(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    OemUidOwnerValue* firewallMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
    if (firewallMatch) {
        return firewallMatch->rule 
            & FIREWALL_WLAN_MATCH ? BPF_MATCH : BPF_NOMATCH;
    }
    return BPF_NOMATCH;
}
// > GMS-CORE : end

//< QBOX : START
DEFINE_BPF_PROG("skfilter/qbox/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_qbox_prog)
(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    // for SYSTEM UID no need to lookup. Only for user range
    if (is_system_uid(sock_uid)) return BPF_NOMATCH;

    OemUidOwnerValue* qboxMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
    if (qboxMatch) return qboxMatch->rule & QBOX_MATCH;
    return BPF_NOMATCH;
}
//> QBOX : END

LICENSE("Apache 2.0");
CRITICAL("netd");