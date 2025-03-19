/* Copyright (C) 2015-2021 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author XXX Your Name <your@email.com>
 *
 * Decodes XXX describe the protocol
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-gtp.h"

#include "detect.h"
#include "detect-engine-port.h"

#include "util-validate.h"


#define GTP_MAX_PORTS      4
#define GTP_UNSET_PORT     -1
#define GTP_DEFAULT_PORT   2152
#define GTP_DEFAULT_PORT_S "2152"

static bool g_gtp_enabled = true;
static int g_gtp_ports_idx = 0;
static int g_gtp_ports[GTP_MAX_PORTS] = { GTP_DEFAULT_PORT, GTP_UNSET_PORT,
    GTP_UNSET_PORT, GTP_UNSET_PORT };

/* Header layout. Keep things like alignment and endianness in
 * mind while constructing this. */
 typedef struct GtpHdr_ {
    union {
		uint8_t gtp_hdr_info; /**< GTP header info */
		struct {
			uint8_t pn:1;   /**< N-PDU Number present bit */
			uint8_t s:1;    /**< Sequence Number Present bit */
			uint8_t e:1;    /**< Extension Present bit */
			uint8_t res1:1; /**< Reserved */
			uint8_t pt:1;   /**< Protocol Type bit */
			uint8_t ver:3;  /**< Version Number */
		};
	};
	uint8_t msg_type;     /**< GTP message type */
	uint16_t plen;      /**< Total payload length */
	uint32_t teid;      /**< Tunnel endpoint ID */
} __attribute__((__packed__)) GtpHdr;

/* Optional word of GTP header, present if any of E, S, PN is set. */
struct GtpHdrExtWord {
	uint16_t sqn;	      /**< Sequence Number. */
	uint8_t npdu;	      /**< N-PDU number. */
	uint8_t next_ext;     /**< Next Extension Header Type. */
}  __attribute__((__packed__));

bool DecodeGtpEnabledForPort(const uint16_t sp, const uint16_t dp)
{
    SCLogDebug("ports %u->%u ports %d %d %d %d", sp, dp, g_gtp_ports[0], g_gtp_ports[1],
            g_gtp_ports[2], g_gtp_ports[3]);

    if (g_gtp_enabled) {
        for (int i = 0; i < g_gtp_ports_idx; i++) {
            if (g_gtp_ports[i] == GTP_UNSET_PORT)
                return false;

            const int port = g_gtp_ports[i];
            if (port == (const int)sp || port == (const int)dp)
                return true;
        }
    }
    return false;
}

static void DecodeGtpConfigPorts(const char *pstr)
{
    SCLogDebug("parsing \'%s\'", pstr);

    DetectPort *head = NULL;
    DetectPortParse(NULL, &head, pstr);

    g_gtp_ports_idx = 0;
    for (DetectPort *p = head; p != NULL; p = p->next) {
        if (g_gtp_ports_idx >= GTP_MAX_PORTS) {
            SCLogWarning("more than %d Gtp ports defined", GTP_MAX_PORTS);
            break;
        }
        g_gtp_ports[g_gtp_ports_idx++] = (int)p->port;
    }

    DetectPortCleanupList(NULL, head);
}

void DecodeGtpConfig(void)
{
    int enabled = 0;
    if (ConfGetBool("decoder.gtp.enabled", &enabled) == 1) {
        if (enabled) {
            g_gtp_enabled = true;
        } else {
            g_gtp_enabled = false;
        }
    }

    if (g_gtp_enabled) {
        ConfNode *node = ConfGetNode("decoder.gtp.ports");
        if (node && node->val) {
            DecodeGtpConfigPorts(node->val);
        } else {
            DecodeGtpConfigPorts(GTP_DEFAULT_PORT_S);
        }
    }
}

/**
 * \brief Function to decode GTP packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */

int DecodeGtp(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    uint16_t eth_type, hdr_len;
    int decode_tunnel_proto = DECODE_TUNNEL_UNSET;
    uint8_t ip_ver;

    /* Now we can access the header */
    const GtpHdr *hdr = (const GtpHdr *)pkt;

    /* General Gtp packet validation */
    if (unlikely(!g_gtp_enabled))
        return TM_ECODE_FAILED;

    hdr_len = sizeof(GtpHdr);

	if (hdr->e || hdr->s || hdr->pn)
        hdr_len += sizeof(struct GtpHdrExtWord);

    /* Validation: make sure that the input data is big enough to hold
     *             the header */
    if (len < hdr_len) {
        /* in case of errors, we set events. Events are defined in
         * decode-events.h, and are then exposed to the detection
         * engine through detect-engine-events.h */
        //ENGINE_SET_EVENT(p,GTP_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    /* Each packet keeps a count of decoded layers
     * This function increases it and returns false
     * if we have too many decoded layers, such as
     * ethernet/MPLS/ethernet/MPLS... which may
     * lead to stack overflow by a too deep recursion
     */
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    StatsIncr(tv, dtv->counter_gtp);

	/*
	 * Check message type. If message type is 0xff, it is
	 * a GTP data packet. If not, it is a GTP control packet
	 */
	if (hdr->msg_type == 0xff) {
		ip_ver = *(uint8_t *)((char *)hdr + hdr_len);
		ip_ver = (ip_ver) & 0xf0;

        /* Determine first protocol encapsulated after Gtp header */
        SCLogDebug("Gtp ethertype 0x%04x", ip_ver);

        switch (ip_ver) {
            case 0x40:
                SCLogDebug("Gtp found IPv4");
                decode_tunnel_proto = DECODE_TUNNEL_IPV4;
                break;
            case 0x60:
                SCLogDebug("Gtp found IPv6");
                decode_tunnel_proto = DECODE_TUNNEL_IPV6;
                break;
            default:
                SCLogDebug(
                        "Gtp found unsupported Ethertype - expected IPv4, IPv6, ARP, or Ethernet");
                ENGINE_SET_INVALID_EVENT(p, GTP_UNKNOWN_PAYLOAD_TYPE);
        }
    }

    /* Set-up and process inner packet if it is a supported ethertype */
    if (decode_tunnel_proto != DECODE_TUNNEL_UNSET) {
        Packet *tp = PacketTunnelPktSetup(
                tv, dtv, p, pkt + hdr_len, len - hdr_len, decode_tunnel_proto);

        if (tp != NULL) {
            PKT_SET_SRC(tp, PKT_SRC_DECODER_GTP);
            PacketEnqueueNoLock(&tv->decode_pq, tp);
        }
    }

    return TM_ECODE_OK;
}

#ifdef UNITTESTS

/**
 * \test DecodeGtpTest01 tests a good Gtp header with 16-bytes of options.
 * Contains a IPv4 DNS request packet.
 */
static int DecodeGtpTest01(void)
{
    uint8_t raw_gtp[] = {
        0x08, 0x68, 0x08, 0x68, 0x00, 0x5e, 0x00, 0x00,             /* UDP header */
        0x32, 0xff, 0x00, 0x4e, 0x08, 0x02, 0x00, 0x00,             /* Gtp fixed header */
        0x01, 0xf9, 0xff, 0x00,                                     /* Gtp variable options */
        0x45, 0x00, 0x00, 0x4a, 0x8f, 0x32, 0x00, 0x00, 0x40, 0x11, /* IPv4 hdr */
        0x0e, 0x94, 0xc0, 0xa8, 0x6f, 0x14, 0xd0, 0x43, 0xdc, 0xdc, 0xe2, 0xa8, 0x00, 0x35, 0x00, 0x36,
        0xee, 0xa2, 0x63, 0x41, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x31,
        0x30, 0x31, 0x03, 0x31, 0x34, 0x35, 0x03, 0x31, 0x36, 0x36, 0x03, 0x31, 0x32, 0x35, 0x07, 0x69,
        0x6e, 0x2d, 0x61, 0x64, 0x64, 0x72, 0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeGtpConfigPorts(GTP_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_gtp, sizeof(raw_gtp));

    FAIL_IF(p->udph == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(tp->udph == NULL);
    FAIL_IF_NOT(tp->sp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}

/**
 * \test DecodeGtpTest02 tests default port disabled by the config.
 */
static int DecodeGtpTest02(void)
{
    uint8_t raw_gtp[] = {
        0x08, 0x68, 0x08, 0x68, 0x00, 0x3c, 0x00, 0x00,             /* UDP header */
        0x32, 0xff, 0x00, 0x2c, 0x08, 0x02, 0x00, 0x00,             /* Gtp fixed header */
        0x00, 0x0b, 0xff, 0x00,                                     /* Gtp variable options */
        0x45, 0x00, 0x00, 0x28, 0x5c, 0xf0, 0x40, 0x00, 0x80, 0x06, /* IPv4 hdr */
        0x9f, 0x71, 0xc0, 0xa8, 0x6f, 0x14, 0x55, 0x11, 0x79, 0xa0, 0xd1, 0x03, 0x00, 0x50, 0x05, 0xea,
        0x52, 0x40, 0xe4, 0xb9, 0x56, 0x1d, 0x50, 0x10, 0x43, 0xdb, 0x09, 0x36, 0x00, 0x00
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeGtpConfigPorts("1"); /* Set Suricata to use a non-default port for Gtp*/

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_gtp, sizeof(raw_gtp));

    FAIL_IF(p->udph == NULL);
    FAIL_IF(tv.decode_pq.top != NULL); /* Gtp packet should not have been processed */

    DecodeGtpConfigPorts(GTP_DEFAULT_PORT_S); /* Reset Gtp port list for future calls */
    FlowShutdown();
    PacketFree(p);
    PASS;
}

#endif /* UNITTESTS */

void DecodeGtpRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeGtpTest01 -- IPv4 DNS Request", DecodeGtpTest01);
    UtRegisterTest("DecodeGtpTest02 -- Non-standard port configuration", DecodeGtpTest02);
#endif /* UNITTESTS */
}
