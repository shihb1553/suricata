/* Copyright (C) 2015-2020 Open Information Security Foundation
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

/*
 * TODO: Update \author in this file and app-layer-wap1.h.
 * TODO: Implement your app-layer logic with unit tests.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * WAP1.X application layer detector and parser for learning and
 * wap1.x pruposes.
 *
 * This wap1.x implements a simple application layer for something
 * like the echo protocol running on UDP port 2948-2949, 9200-9203.
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"
#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-wap1.h"

#include "util-unittest.h"
#include "util-validate.h"

/* The default port to probe for echo traffic if not provided in the
 * configuration file. */
#define WAP1_DEFAULT_PORT "[2948:2949,9200:9203]"

/* The minimum size for a message. For some protocols this might
 * be the size of a header. */
#define WAP1_MIN_FRAME_LEN 4

/**
 * \brief Probe the input to see if it looks like +OK.
 *
 * \retval ALPROTO_WAP1 if it looks like +OK, otherwise
 *     ALPROTO_UNKNOWN.
 */
static  __attribute__((unused)) AppProto WAP1ProbingParser(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    if (input_len >= WAP1_MIN_FRAME_LEN) {
        SCLogDebug("Detected as ALPROTO_WAP1.");
        return ALPROTO_WAP1;
    }

    SCLogDebug("Protocol not detected as ALPROTO_WAP1.");
    return ALPROTO_UNKNOWN;
}


void RegisterWAP1Parsers(void)
{
    const char *proto_name = "wap1";

    /* Check if WAP1.X UDP detection is enabled. If it does not exist in
     * the configuration file then it will be enabled by default. */

    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_WAP1, proto_name);

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                                          WAP1_DEFAULT_PORT,
                                          ALPROTO_WAP1,
                                          0, 0,
                                          STREAM_TOSERVER,
                                          WAP1ProbingParser, WAP1ProbingParser);
        } else {
            if (AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                                                    proto_name, ALPROTO_WAP1,
                                                    0, 0,
                                                    WAP1ProbingParser, WAP1ProbingParser) == 0) {
                AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                                              WAP1_DEFAULT_PORT,
                                              ALPROTO_WAP1,
                                              0, 0,
                                              STREAM_TOSERVER,
                                              WAP1ProbingParser, WAP1ProbingParser);
            }
        }
    }

    else {
        //SCLogNotice("Protocol detecter and parser disabled for WAP1.X.");
        return;
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_WAP1,
        WAP1ParserRegisterTests);
#endif
}

#ifdef UNITTESTS
#endif

void WAP1ParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif
}
