#include "suricata.h"
#include "suricata-common.h"
#include "debug.h"

#include "app-layer-htp.h"
#include "app-layer-htp-file.h"
#include "app-layer-mmse.h"

/*
 * Header field values
 */
/* MMS 1.0 */
#define MM_BCC_HDR              0x81    /* Bcc                          */
#define MM_CC_HDR               0x82    /* Cc                           */
#define MM_CLOCATION_HDR        0x83    /* X-Mms-Content-Location       */
#define MM_CTYPE_HDR            0x84    /* Content-Type                 */
#define MM_DATE_HDR             0x85    /* Date                         */
#define MM_DREPORT_HDR          0x86    /* X-Mms-Delivery-Report        */
#define MM_DTIME_HDR            0x87    /* X-Mms-Delivery-Time          */
#define MM_EXPIRY_HDR           0x88    /* X-Mms-Expiry                 */
#define MM_FROM_HDR             0x89    /* From                         */
#define MM_MCLASS_HDR           0x8A    /* X-Mms-Message-Class          */
#define MM_MID_HDR              0x8B    /* Message-ID                   */
#define MM_MTYPE_HDR            0x8C    /* X-Mms-Message-Type           */
#define MM_VERSION_HDR          0x8D    /* X-Mms-MMS-Version            */
#define MM_MSIZE_HDR            0x8E    /* X-Mms-Message-Size           */
#define MM_PRIORITY_HDR         0x8F    /* X-Mms-Priority               */
#define MM_RREPLY_HDR           0x90    /* X-Mms-Read-Reply             */
#define MM_RALLOWED_HDR         0x91    /* X-Mms-Report-Allowed         */
#define MM_RSTATUS_HDR          0x92    /* X-Mms-Response-Status        */
#define MM_RTEXT_HDR            0x93    /* X-Mms-Response-Text          */
#define MM_SVISIBILITY_HDR      0x94    /* X-Mms-Sender-Visibility      */
#define MM_STATUS_HDR           0x95    /* X-Mms-Status                 */
#define MM_SUBJECT_HDR          0x96    /* Subject                      */
#define MM_TO_HDR               0x97    /* To                           */
#define MM_TID_HDR              0x98    /* X-Mms-Transaction-Id         */
/* MMS 1.1 */
#define MM_RETRIEVE_STATUS_HDR  0x99    /* X-Mms-Retrieve-Status        */
#define MM_RETRIEVE_TEXT_HDR    0x9A    /* X-Mms-Retrieve-Text          */
#define MM_READ_STATUS_HDR      0x9B    /* X-Mms-Read-Status            */
#define MM_REPLY_CHARGING_HDR   0x9C    /* X-Mms-Reply-Charging         */
#define MM_REPLY_CHARGING_DEADLINE_HDR  \
                                0x9D    /* X-Mms-Reply-Charging-Deadline*/
#define MM_REPLY_CHARGING_ID_HDR        \
                                0x9E    /* X-Mms-Reply-Charging-ID      */
#define MM_REPLY_CHARGING_SIZE_HDR      \
                                0x9F    /* X-Mms-Reply-Charging-Size    */
#define MM_PREV_SENT_BY_HDR     0xA0    /* X-Mms-Previously-Sent-By     */
#define MM_PREV_SENT_DATE_HDR   0xA1    /* X-Mms-Previously-Sent-Date   */
/* MMS 1.2 */
#define MM_STORE_HDR            0xA2    /* X-Mms-Store                  */
#define MM_MM_STATE_HDR         0xA3    /* X-Mms-MM-State               */
#define MM_MM_FLAGS_HDR         0xA4    /* X-Mms-MM-Flags               */
#define MM_STORE_STATUS_HDR     0xA5    /* X-Mms-Store-Status           */
#define MM_STORE_STATUS_TEXT_HDR        \
                                0xA6    /* X-Mms-Store-Status-Text      */
#define MM_STORED_HDR           0xA7    /* X-Mms-Stored                 */
#define MM_ATTRIBUTES_HDR       0xA8    /* X-Mms-Attributes             */
#define MM_TOTALS_HDR           0xA9    /* X-Mms-Totals                 */
#define MM_MBOX_TOTALS_HDR      0xAA    /* X-Mms-Mbox-Totals            */
#define MM_QUOTAS_HDR           0xAB    /* X-Mms-Quotas                 */
#define MM_MBOX_QUOTAS_HDR      0xAC    /* X-Mms-Mbox-Quotas            */
#define MM_MBOX_MSG_COUNT_HDR   0xAD    /* X-Mms-Message-Count          */
#define MM_CONTENT_HDR          0xAE    /* Content                      */
#define MM_START_HDR            0xAF    /* X-Mms-Start                  */
#define MM_ADDITIONAL_HDR       0xB0    /* Additional-headers           */
#define MM_DISTRIBUION_IND_HDR  0xB1    /* X-Mms-Distribution-Indicator */
#define MM_ELEMENT_DESCR_HDR    0xB2    /* X-Mms-Element-Descriptor     */
#define MM_LIMIT_HDR            0xB3    /* X-Mms-Limit                  */

typedef struct val_string_s {
    uint8_t val;
    const char *name;
} val_string;

typedef struct val_string_s val_string;

static const val_string mm_header[] = {
        /* MMS 1.0 */
        { MM_BCC_HDR,                   "Bcc" },
        { MM_CC_HDR,                    "Cc" },
        { MM_CLOCATION_HDR,             "X-Mms-Content-Location" },
        { MM_CTYPE_HDR,                 "X-Mms-Content-Type" },
        { MM_DATE_HDR,                  "Date" },
        { MM_DREPORT_HDR,               "X-Mms-Delivery-Report" },
        { MM_DTIME_HDR,                 "X-Mms-Delivery-Time" },
        { MM_EXPIRY_HDR,                "X-Mms-Expiry" },
        { MM_FROM_HDR,                  "From" },
        { MM_MCLASS_HDR,                "X-Mms-Message-Class" },
        { MM_MID_HDR,                   "Message-ID" },
        { MM_MTYPE_HDR,                 "X-Mms-Message-Type" },
        { MM_VERSION_HDR,               "X-Mms-MMS-Version" },
        { MM_MSIZE_HDR,                 "X-Mms-Message-Size" },
        { MM_PRIORITY_HDR,              "X-Mms-Priority" },
        { MM_RREPLY_HDR,                "X-Mms-Read-Reply" },
        { MM_RALLOWED_HDR,              "X-Mms-Report-Allowed" },
        { MM_RSTATUS_HDR,               "X-Mms-Response-Status" },
        { MM_RTEXT_HDR,                 "X-Mms-Response-Text" },
        { MM_SVISIBILITY_HDR,           "X-Mms-Sender-Visibility" },
        { MM_STATUS_HDR,                "X-Mms-Status" },
        { MM_SUBJECT_HDR,               "Subject" },
        { MM_TO_HDR,                    "To" },
        { MM_TID_HDR,                   "X-Mms-Transaction-Id" },
        /* MMS 1.1 */
        { MM_RETRIEVE_STATUS_HDR,       "X-Mms-Retrieve-Status" },
        { MM_RETRIEVE_TEXT_HDR,         "X-Mms-Retrieve-Text" },
        { MM_READ_STATUS_HDR,           "X-Mms-Read-Status" },
        { MM_REPLY_CHARGING_HDR,        "X-Mms-Reply-Charging" },
        { MM_REPLY_CHARGING_DEADLINE_HDR,
                                        "X-Mms-Reply-Charging-Deadline" },
        { MM_REPLY_CHARGING_ID_HDR,     "X-Mms-Reply-Charging-ID" },
        { MM_REPLY_CHARGING_SIZE_HDR,   "X-Mms-Reply-Charging-Size" },
        { MM_PREV_SENT_BY_HDR,          "X-Mms-Previously-Sent-By" },
        { MM_PREV_SENT_DATE_HDR,        "X-Mms-Previously-Sent-Date" },
        /* MMS 1.2 */
        { MM_STORE_HDR,                 "X-Mms-Store" },
        { MM_MM_STATE_HDR,              "X-Mms-MM-State" },
        { MM_MM_FLAGS_HDR,              "X-Mms-MM-Flags" },
        { MM_STORE_STATUS_HDR,          "X-Mms-Store-Status" },
        { MM_STORE_STATUS_TEXT_HDR,     "X-Mms-Store-Status-Text" },
        { MM_STORED_HDR,                "X-Mms-Stored" },
        { MM_ATTRIBUTES_HDR,            "X-Mms-Attributes" },
        { MM_TOTALS_HDR,                "X-Mms-Totals" },
        { MM_MBOX_TOTALS_HDR,           "X-Mms-Mbox-Totals" },
        { MM_QUOTAS_HDR,                "X-Mms-Quotas" },
        { MM_MBOX_QUOTAS_HDR,           "X-Mms-Mbox-Quotas" },
        { MM_MBOX_MSG_COUNT_HDR,        "X-Mms-Message-Count" },
        { MM_CONTENT_HDR,               "Content" },
        { MM_START_HDR,                 "X-Mms-Start" },
        { MM_ADDITIONAL_HDR,            "Additional-headers" },
        { MM_DISTRIBUION_IND_HDR,       "X-Mms-Distribution-Indicator" },
        { MM_ELEMENT_DESCR_HDR,         "X-Mms-Element-Descriptor" },
        { MM_LIMIT_HDR,                 "X-Mms-Limit" },
        { 0x00, NULL },
};

/*
 * Valuestrings for PDU types
 */
/* MMS 1.0 */
#define PDU_M_SEND_REQ          0x80
#define PDU_M_SEND_CONF         0x81
#define PDU_M_NOTIFICATION_IND  0x82
#define PDU_M_NOTIFYRESP_IND    0x83
#define PDU_M_RETRIEVE_CONF     0x84
#define PDU_M_ACKNOWLEDGE_IND   0x85
#define PDU_M_DELIVERY_IND      0x86
/* MMS 1.1 */
#define PDU_M_READ_REC_IND      0x87
#define PDU_M_READ_ORIG_IND     0x88
#define PDU_M_FORWARD_REQ       0x89
#define PDU_M_FORWARD_CONF      0x8A
/* MMS 1.2 */
#define PDU_M_MBOX_STORE_REQ    0x8B
#define PDU_M_MBOX_STORE_CONF   0x8C
#define PDU_M_MBOX_VIEW_REQ     0x8D
#define PDU_M_MBOX_VIEW_CONF    0x8E
#define PDU_M_MBOX_UPLOAD_REQ   0x8F
#define PDU_M_MBOX_UPLOAD_CONF  0x90
#define PDU_M_MBOX_DELETE_REQ   0x91
#define PDU_M_MBOX_DELETE_CONF  0x92
#define PDU_M_MBOX_DESCR        0x93

#define pdu_has_content(pdut) \
        (  ((pdut) == PDU_M_SEND_REQ) \
        || ((pdut) == PDU_M_DELIVERY_IND) \
        || ((pdut) == PDU_M_RETRIEVE_CONF) \
        || ((pdut) == PDU_M_MBOX_VIEW_CONF) \
        || ((pdut) == PDU_M_MBOX_DESCR) \
        || ((pdut) == PDU_M_MBOX_UPLOAD_REQ) \
        )

/* Don't parse following detail now */
#if 0
static const val_string message_type[] = {
    /* MMS 1.0 */
    { PDU_M_SEND_REQ,           "m-send-req" },
    { PDU_M_SEND_CONF,          "m-send-conf" },
    { PDU_M_NOTIFICATION_IND,   "m-notification-ind" },
    { PDU_M_NOTIFYRESP_IND,     "m-notifyresp-ind" },
    { PDU_M_RETRIEVE_CONF,      "m-retrieve-conf" },
    { PDU_M_ACKNOWLEDGE_IND,    "m-acknowledge-ind" },
    { PDU_M_DELIVERY_IND,       "m-delivery-ind" },
    /* MMS 1.1 */
    { PDU_M_READ_REC_IND,       "m-read-rec-ind" },
    { PDU_M_READ_ORIG_IND,      "m-read-orig-ind" },
    { PDU_M_FORWARD_REQ,        "m-forward-req" },
    { PDU_M_FORWARD_CONF,       "m-forward-conf" },
    /* MMS 1.2 */
    { PDU_M_MBOX_STORE_REQ,     "m-mbox-store-req" },
    { PDU_M_MBOX_STORE_CONF,    "m-mbox-store-conf" },
    { PDU_M_MBOX_VIEW_REQ,      "m-mbox-view-req" },
    { PDU_M_MBOX_VIEW_CONF,     "m-mbox-view-conf" },
    { PDU_M_MBOX_UPLOAD_REQ,    "m-mbox-upload-req" },
    { PDU_M_MBOX_UPLOAD_CONF,   "m-mbox-upload-conf" },
    { PDU_M_MBOX_DELETE_REQ,    "m-mbox-delete-req" },
    { PDU_M_MBOX_DELETE_CONF,   "m-mbox-delete-conf" },
    { PDU_M_MBOX_DESCR,         "m-mbox-descr" },
    { 0x00, NULL },
};

static const val_string vals_yes_no[] = {
    { 0x80, "Yes" },
    { 0x81, "No" },
    { 0x00, NULL },
};

static const val_string vals_message_class[] = {
    { 0x80, "Personal" },
    { 0x81, "Advertisement" },
    { 0x82, "Informational" },
    { 0x83, "Auto" },
    { 0x00, NULL },
};

static const val_string vals_priority[] = {
    { 0x80, "Low" },
    { 0x81, "Normal" },
    { 0x82, "High" },
    { 0x00, NULL },
};

static const val_string response_status[] = {
    /* MMS 1.0 - obsolete as from MMS 1.1 */
    { 0x80, "Ok" },
    { 0x81, "Unspecified" },
    { 0x82, "Service denied" },
    { 0x83, "Message format corrupt" },
    { 0x84, "Sending address unresolved" },
    { 0x85, "Message not found" },
    { 0x86, "Network problem" },
    { 0x87, "Content not accepted" },
    { 0x88, "Unsupported message" },

    /*
     * Transient errors
     */
    /* MMS 1.1 */
    { 0xC0, "Transient failure" },
    { 0xC1, "Transient: Sending address unresolved" },
    { 0xC2, "Transient: Message not found" },
    { 0xC3, "Transient: Network problem" },
    /* MMS 1.2 */
    { 0xC4, "Transient: Partial success" },

    /*
     * Permanent errors
     */
    /* MMS 1.1 */
    { 0xE0, "Permanent failure" },
    { 0xE1, "Permanent: Service denied" },
    { 0xE2, "Permanent: Message format corrupt" },
    { 0xE3, "Permanent: Sending address unresolved" },
    { 0xE4, "Permanent: Message not found" },
    { 0xE5, "Permanent: Content not accepted" },
    { 0xE6, "Permanent: Reply charging limitations not met" },
    { 0xE7, "Permanent: Reply charging request not accepted" },
    { 0xE8, "Permanent: Reply charging forwarding denied" },
    { 0xE9, "Permanent: Reply charging not supported" },
    /* MMS 1.2 */
    { 0xEA, "Permanent: Address hiding not supported" },

    { 0x00, NULL },
};

static const val_string sender_visibility[] = {
    { 0x80, "Hide" },
    { 0x81, "Show" },
    { 0x00, NULL },
};

static const val_string message_status[] = {
    /* MMS 1.0 */
    { 0x80, "Expired" },
    { 0x81, "Retrieved" },
    { 0x82, "Rejected" },
    { 0x83, "Deferred" },
    { 0x84, "Unrecognized" },
    /* MMS 1.1 */
    { 0x85, "Indeterminate" },
    { 0x86, "Forwarded" },
    /* MMS 1.2 */
    { 0x87, "Unreachable" },

    { 0x00, NULL },
};

static const val_string vals_retrieve_status[] = {
    /* MMS 1.1 */
    { 0x80, "Ok" },

    /*
     * Transient errors
     */
    /* MMS 1.1 */
    { 0xC0, "Transient failure" },
    { 0xC1, "Transient: Message not found" },
    { 0xC2, "Transient: Network problem" },

    /*
     * Permanent errors
     */
    /* MMS 1.1 */
    { 0xE0, "Permanent failure" },
    { 0xE1, "Permanent: Service denied" },
    { 0xE2, "Permanent: Message not found" },
    { 0xE3, "Permanent: Content unsupported" },

    { 0x00, NULL },
};

static const val_string read_status[] = {
    { 0x80, "Read" },
    { 0x81, "Deleted without being read" },

    { 0x00, NULL },
};

static const val_string reply_charging[] = {
    { 0x80, "Requested" },
    { 0x81, "Requested text only" },
    { 0x82, "Accepted" },
    { 0x83, "Accepted text only" },

    { 0x00, NULL },
};
#endif


/* Well-known content-type */
#if 0
name="*/*" code="0"
name="text/*" code="1"
name="text/html" code="2"
name="text/plain" code="3"
name="text/x-hdml" code="4"
name="text/x-ttml" code="5"
name="text/x-vCalendar" code="6"
name="text/x-vCard" code="7"
name="text/vnd.wap.wml" code="8"
name="text/vnd.wap.wmlscript" code="9"
name="text/vnd.wap.wta-event" code="10"
name="multipart/*" code="11"
name="multipart/mixed" code="12"
name="multipart/form-data" code="13"
name="multipart/byterantes" code="14"
name="multipart/alternative" code="15"
name="application/*" code="16"
name="application/java-vm" code="17"
name="application/x-www-form-urlencoded" code="18"
name="application/x-hdmlc" code="19"
name="application/vnd.wap.wmlc" code="20"
name="application/vnd.wap.wmlscriptc" code="21"
name="application/vnd.wap.wta-eventc" code="22"
name="application/vnd.wap.uaprof" code="23"
name="application/vnd.wap.wtls-ca-certificate" code="24"
name="application/vnd.wap.wtls-user-certificate" code="25"
name="application/x-x509-ca-cert" code="26"
name="application/x-x509-user-cert" code="27"
name="image/*" code="28"
name="image/gif" code="29"
name="image/jpeg" code="30"
name="image/tiff" code="31"
name="image/png" code="32"
name="image/vnd.wap.wbmp" code="33"
name="application/vnd.wap.multipart.*" code="34"
name="application/vnd.wap.multipart.mixed" code="35"
name="application/vnd.wap.multipart.form-data" code="36"
name="application/vnd.wap.multipart.byteranges" code="37"
name="application/vnd.wap.multipart.alternative" code="38"
name="application/xml" code="39"
name="text/xml" code="40"
name="application/vnd.wap.wbxml" code="41"
name="application/x-x968-cross-cert" code="42"
name="application/x-x968-ca-cert" code="43"
name="application/x-x968-user-cert" code="44"
name="text/vnd.wap.si" code="45"
name="application/vnd.wap.sic" code="46"
name="text/vnd.wap.sl" code="47"
name="application/vnd.wap.slc" code="48"
name="text/vnd.wap.co" code="49"
name="application/vnd.wap.coc" code="50"
name="application/vnd.wap.multipart.related" code="51"
name="application/vnd.wap.sia" code="52"
name="text/vnd.wap.connectivity-xml" code="53"
name="application/vnd.wap.connectivity-wbxml" code="54"
name="application/pkcs7-mime" code="55"
name="application/vnd.wap.hashed-certificate" code="56"
name="application/vnd.wap.signed-certificate" code="57"
name="application/vnd.wap.cert-response" code="58"
name="application/xhtml+xml" code="59"
name="application/wml+xml" code="60"
name="text/css" code="61"
name="application/vnd.wap.mms-message" code="62"
name="application/vnd.wap.rollover-certificate" code="63"
name="application/vnd.wap.locc+wbxml" code="64"
name="application/vnd.wap.loc+xml" code="65"
name="application/vnd.syncml.dm+wbxml" code="66"
name="application/vnd.syncml.dm+xml" code="67"
name="application/vnd.syncml.notification" code="68"
name="application/vnd.wap.xhtml+xml" code="69"
name="application/vnd.wv.csp.cir" code="70"
name="application/vnd.oma.dd+xml" code="71"
name="application/vnd.oma.drm.message" code="72"
name="application/vnd.oma.drm.content" code="73"
name="application/vnd.oma.drm.rights+xml" code="74"
name="application/vnd.oma.drm.rights+wbxml" code="75"
name="application/vnd.wv.csp+xml" code="76"
name="application/vnd.wv.csp+wbxml" code="77"
name="application/vnd.syncml.ds.notification" code="78"
name="audio/*" code="79"
name="video/*" code="80"
name="application/vnd.oma.dd2+xml" code="81"
name="application/mikey" code="82"
name="application/vnd.oma.dcd" code="83"
name="application/vnd.oma.dcdc" code="84"
#endif

static const val_string mm_content_types[] = {
    /* Well-known media types */
    /* XXX: hack: "..." "..." used to define several strings so that checkAPIs & etc won't see a 'start of comment' */
    { 0x00, "*" "/" "*" },
    { 0x01, "text/" "*" },
    { 0x02, "text/html" },
    { 0x03, "text/plain" },
    { 0x04, "text/x-hdml" },
    { 0x05, "text/x-ttml" },
    { 0x06, "text/x-vCalendar" },
    { 0x07, "text/x-vCard" },
    { 0x08, "text/vnd.wap.wml" },
    { 0x09, "text/vnd.wap.wmlscript" },
    { 0x0A, "text/vnd.wap.channel" },
    { 0x0B, "multipart/" "*" },
    { 0x0C, "multipart/mixed" },
    { 0x0D, "multipart/form-data" },
    { 0x0E, "multipart/byteranges" },
    { 0x0F, "multipart/alternative" },
    { 0x10, "application/" "*" },
    { 0x11, "application/java-vm" },
    { 0x12, "application/x-www-form-urlencoded" },
    { 0x13, "application/x-hdmlc" },
    { 0x14, "application/vnd.wap.wmlc" },
    { 0x15, "application/vnd.wap.wmlscriptc" },
    { 0x16, "application/vnd.wap.channelc" },
    { 0x17, "application/vnd.wap.uaprof" },
    { 0x18, "application/vnd.wap.wtls-ca-certificate" },
    { 0x19, "application/vnd.wap.wtls-user-certificate" },
    { 0x1A, "application/x-x509-ca-cert" },
    { 0x1B, "application/x-x509-user-cert" },
    { 0x1C, "image/" "*" },
    { 0x1D, "image/gif" },
    { 0x1E, "image/jpeg" },
    { 0x1F, "image/tiff" },
    { 0x20, "image/png" },
    { 0x21, "image/vnd.wap.wbmp" },
    { 0x22, "application/vnd.wap.multipart.*" },
    { 0x23, "application/vnd.wap.multipart.mixed" },
    { 0x24, "application/vnd.wap.multipart.form-data" },
    { 0x25, "application/vnd.wap.multipart.byteranges" },
    { 0x26, "application/vnd.wap.multipart.alternative" },
    { 0x27, "application/xml" },
    { 0x28, "text/xml" },
    { 0x29, "application/vnd.wap.wbxml" },
    { 0x2A, "application/x-x968-cross-cert" },
    { 0x2B, "application/x-x968-ca-cert" },
    { 0x2C, "application/x-x968-user-cert" },
    { 0x2D, "text/vnd.wap.si" },
    { 0x2E, "application/vnd.wap.sic" },
    { 0x2F, "text/vnd.wap.sl" },
    { 0x30, "application/vnd.wap.slc" },
    { 0x31, "text/vnd.wap.co" },
    { 0x32, "application/vnd.wap.coc" },
    { 0x33, "application/vnd.wap.multipart.related" },
    { 0x34, "application/vnd.wap.sia" },
    { 0x35, "text/vnd.wap.connectivity-xml" },
    { 0x36, "application/vnd.wap.connectivity-wbxml" },
    { 0x37, "application/pkcs7-mime" },
    { 0x38, "application/vnd.wap.hashed-certificate" },
    { 0x39, "application/vnd.wap.signed-certificate" },
    { 0x3A, "application/vnd.wap.cert-response" },
    { 0x3B, "application/xhtml+xml" },
    { 0x3C, "application/wml+xml" },
    { 0x3D, "text/css" },
    { 0x3E, "application/vnd.wap.mms-message" },
    { 0x3F, "application/vnd.wap.rollover-certificate" },
    { 0x40, "application/vnd.wap.locc+wbxml"},
    { 0x41, "application/vnd.wap.loc+xml"},
    { 0x42, "application/vnd.syncml.dm+wbxml"},
    { 0x43, "application/vnd.syncml.dm+xml"},
    { 0x44, "application/vnd.syncml.notification"},
    { 0x45, "application/vnd.wap.xhtml+xml"},
    { 0x46, "application/vnd.wv.csp.cir"},
    { 0x47, "application/vnd.oma.dd+xml"},
    { 0x48, "application/vnd.oma.drm.message"},
    { 0x49, "application/vnd.oma.drm.content"},
    { 0x4A, "application/vnd.oma.drm.rights+xml"},
    { 0x4B, "application/vnd.oma.drm.rights+wbxml"},
    { 0x4C, "application/vnd.wv.csp+xml"},
    { 0x4D, "application/vnd.wv.csp+wbxml"},
    { 0x5A, "application/octet-stream"},
#if 0
    /* The following media types are registered by 3rd parties */
    { 0x0201, "application/vnd.uplanet.cachop-wbxml" },
    { 0x0202, "application/vnd.uplanet.signal" },
    { 0x0203, "application/vnd.uplanet.alert-wbxml" },
    { 0x0204, "application/vnd.uplanet.list-wbxml" },
    { 0x0205, "application/vnd.uplanet.listcmd-wbxml" },
    { 0x0206, "application/vnd.uplanet.channel-wbxml" },
    { 0x0207, "application/vnd.uplanet.provisioning-status-uri" },
    { 0x0208, "x-wap.multipart/vnd.uplanet.header-set" },
    { 0x0209, "application/vnd.uplanet.bearer-choice-wbxml" },
    { 0x020A, "application/vnd.phonecom.mmc-wbxml" },
    { 0x020B, "application/vnd.nokia.syncset+wbxml" },
    { 0x020C, "image/x-up-wpng"},
    { 0x0300, "application/iota.mmc-wbxml"},
    { 0x0301, "application/iota.mmc-xml"},
#endif
    { 0x00, NULL }
};

static const val_string parameter_type[] = {
    { 0x00,         "Q: Q-value" },
    { 0x01,         "Well-known-charset" },
    { 0x02,         "Level: Version-value" },
    { 0x03,         "Integer-value" },
    { 0x05,         "Name (Text-string)" },
    { 0x06,         "Filename (Text-string)" },
    { 0x07,         "Differences" },
    { 0x08,         "Padding" },
    { 0x09,         "Special Constrained-encoding" },
    { 0x0A,         "Start (Text-string)" },
    { 0x0B,         "Start-info (Text-string)" },
    { 0x0C,         "Comment (Text-string)" },
    { 0x0D,         "Domain (Text-string)" },
    { 0x0E,         "Max-Age" },
    { 0x0F,         "Path (Text-string)" },
    { 0x10,         "Secure" },
    { 0x11,         "SEC: Short-integer" },
    { 0x12,         "MAC: Text-value" },
    { 0x13,         "Creation-date" },
    { 0x14,         "Modification-date" },
    { 0x15,         "Read-date" },
    { 0x16,         "Size: Integer-value" },
    { 0x17,         "Name (Text-value)" },
    { 0x18,         "Filename (Text-value)" },
    { 0x19,         "Start (with multipart/related) (Text-value)" },
    { 0x1A,         "Start-info (with multipart/related) (Text-value)" },
    { 0x1B,         "Comment (Text-value)" },
    { 0x1C,         "Domain (Text-value)" },
    { 0x1D,         "Path (Text-value)" },

    { 0x00, NULL }
};

/*
 * Field names.
 */
#define FN_ACCEPT                 0x00
#define FN_ACCEPT_CHARSET_DEP     0x01    /* encoding version 1.1, deprecated */
#define FN_ACCEPT_ENCODING_DEP    0x02    /* encoding version 1.1, deprecated */
#define FN_ACCEPT_LANGUAGE        0x03
#define FN_ACCEPT_RANGES          0x04
#define FN_AGE                    0x05
#define FN_ALLOW                  0x06
#define FN_AUTHORIZATION          0x07
#define FN_CACHE_CONTROL_DEP      0x08    /* encoding version 1.1, deprecated */
#define FN_CONNECTION             0x09
#define FN_CONTENT_BASE           0x0A
#define FN_CONTENT_ENCODING       0x0B
#define FN_CONTENT_LANGUAGE       0x0C
#define FN_CONTENT_LENGTH         0x0D
#define FN_CONTENT_LOCATION       0x0E
#define FN_CONTENT_MD5            0x0F
#define FN_CONTENT_RANGE_DEP      0x10    /* encoding version 1.1, deprecated */
#define FN_CONTENT_TYPE           0x11
#define FN_DATE                   0x12
#define FN_ETAG                   0x13
#define FN_EXPIRES                0x14
#define FN_FROM                   0x15
#define FN_HOST                   0x16
#define FN_IF_MODIFIED_SINCE      0x17
#define FN_IF_MATCH               0x18
#define FN_IF_NONE_MATCH          0x19
#define FN_IF_RANGE               0x1A
#define FN_IF_UNMODIFIED_SINCE    0x1B
#define FN_LOCATION               0x1C
#define FN_LAST_MODIFIED          0x1D
#define FN_MAX_FORWARDS           0x1E
#define FN_PRAGMA                 0x1F
#define FN_PROXY_AUTHENTICATE     0x20
#define FN_PROXY_AUTHORIZATION    0x21
#define FN_PUBLIC                 0x22
#define FN_RANGE                  0x23
#define FN_REFERER                0x24
#define FN_RETRY_AFTER            0x25
#define FN_SERVER                 0x26
#define FN_TRANSFER_ENCODING      0x27
#define FN_UPGRADE                0x28
#define FN_USER_AGENT             0x29
#define FN_VARY                   0x2A
#define FN_VIA                    0x2B
#define FN_WARNING                0x2C
#define FN_WWW_AUTHENTICATE       0x2D
#define FN_CONTENT_DISPOSITION    0x2E
#define FN_X_WAP_APPLICATION_ID   0x2F
#define FN_X_WAP_CONTENT_URI      0x30
#define FN_X_WAP_INITIATOR_URI    0x31
#define FN_ACCEPT_APPLICATION     0x32
#define FN_BEARER_INDICATION      0x33
#define FN_PUSH_FLAG              0x34
#define FN_PROFILE                0x35
#define FN_PROFILE_DIFF           0x36
#define FN_PROFILE_WARNING        0x37
#define FN_EXPECT                 0x38
#define FN_TE                     0x39
#define FN_TRAILER                0x3A
#define FN_ACCEPT_CHARSET         0x3B    /* encoding version 1.3 */
#define FN_ACCEPT_ENCODING        0x3C    /* encoding version 1.3 */
#define FN_CACHE_CONTROL          0x3D    /* encoding version 1.3 */
#define FN_CONTENT_RANGE          0x3E    /* encoding version 1.3 */
#define FN_X_WAP_TOD              0x3F
#define FN_CONTENT_ID             0x40
#define FN_SET_COOKIE             0x41
#define FN_COOKIE                 0x42
#define FN_ENCODING_VERSION       0x43
#define FN_PROFILE_WARNING14      0x44    /* encoding version 1.4 */
#define FN_CONTENT_DISPOSITION14  0x45    /* encoding version 1.4 */
#define FN_X_WAP_SECURITY         0x46
#define FN_CACHE_CONTROL14        0x47    /* encoding version 1.4 */
#define FN_EXPECT15               0x48    /* encoding version 1.5 */
#define FN_X_WAP_LOC_INVOCATION   0x49
#define FN_X_WAP_LOC_DELIVERY     0x4A


static const val_string vals_field_names[] = {
    { FN_ACCEPT,               "Accept" },
    { FN_ACCEPT_CHARSET_DEP,   "Accept-Charset (encoding 1.1)" },
    { FN_ACCEPT_ENCODING_DEP,  "Accept-Encoding (encoding 1.1)" },
    { FN_ACCEPT_LANGUAGE,      "Accept-Language" },
    { FN_ACCEPT_RANGES,        "Accept-Ranges" },
    { FN_AGE,                  "Age" },
    { FN_ALLOW,                "Allow" },
    { FN_AUTHORIZATION,        "Authorization" },
    { FN_CACHE_CONTROL_DEP,    "Cache-Control (encoding 1.1)" },
    { FN_CONNECTION,           "Connection" },
    { FN_CONTENT_BASE,         "Content-Base" },
    { FN_CONTENT_ENCODING,     "Content-Encoding" },
    { FN_CONTENT_LANGUAGE,     "Content-Language" },
    { FN_CONTENT_LENGTH,       "Content-Length" },
    { FN_CONTENT_LOCATION,     "Content-Location" },
    { FN_CONTENT_MD5,          "Content-MD5" },
    { FN_CONTENT_RANGE_DEP,    "Content-Range (encoding 1.1)" },
    { FN_CONTENT_TYPE,         "Content-Type" },
    { FN_DATE,                 "Date" },
    { FN_ETAG,                 "ETag" },
    { FN_EXPIRES,              "Expires" },
    { FN_FROM,                 "From" },
    { FN_HOST,                 "Host" },
    { FN_IF_MODIFIED_SINCE,    "If-Modified-Since" },
    { FN_IF_MATCH,             "If-Match" },
    { FN_IF_NONE_MATCH,        "If-None-Match" },
    { FN_IF_RANGE,             "If-Range" },
    { FN_IF_UNMODIFIED_SINCE,  "If-Unmodified-Since" },
    { FN_LOCATION,             "Location" },
    { FN_LAST_MODIFIED,        "Last-Modified" },
    { FN_MAX_FORWARDS,         "Max-Forwards" },
    { FN_PRAGMA,               "Pragma" },
    { FN_PROXY_AUTHENTICATE,   "Proxy-Authenticate" },
    { FN_PROXY_AUTHORIZATION,  "Proxy-Authorization" },
    { FN_PUBLIC,               "Public" },
    { FN_RANGE,                "Range" },
    { FN_REFERER,              "Referer" },
    { FN_RETRY_AFTER,          "Retry-After" },
    { FN_SERVER,               "Server" },
    { FN_TRANSFER_ENCODING,    "Transfer-Encoding" },
    { FN_UPGRADE,              "Upgrade" },
    { FN_USER_AGENT,           "User-Agent" },
    { FN_VARY,                 "Vary" },
    { FN_VIA,                  "Via" },
    { FN_WARNING,              "Warning" },
    { FN_WWW_AUTHENTICATE,     "WWW-Authenticate" },
    { FN_CONTENT_DISPOSITION,  "Content-Disposition" },
    { FN_X_WAP_APPLICATION_ID, "X-Wap-Application-ID" },
    { FN_X_WAP_CONTENT_URI,    "X-Wap-Content-URI" },
    { FN_X_WAP_INITIATOR_URI,  "X-Wap-Initiator-URI" },
    { FN_ACCEPT_APPLICATION,   "Accept-Application" },
    { FN_BEARER_INDICATION,    "Bearer-Indication" },
    { FN_PUSH_FLAG,            "Push-Flag" },
    { FN_PROFILE,              "Profile" },
    { FN_PROFILE_DIFF,         "Profile-Diff" },
    { FN_PROFILE_WARNING,      "Profile-Warning" },
    { FN_EXPECT,               "Expect" },
    { FN_TE,                   "TE" },
    { FN_TRAILER,              "Trailer" },
    { FN_ACCEPT_CHARSET,       "Accept-Charset" },
    { FN_ACCEPT_ENCODING,      "Accept-Encoding" },
    { FN_CACHE_CONTROL,        "Cache-Control" },
    { FN_CONTENT_RANGE,        "Content-Range" },
    { FN_X_WAP_TOD,            "X-Wap-Tod" },
    { FN_CONTENT_ID,           "Content-ID" },
    { FN_SET_COOKIE,           "Set-Cookie" },
    { FN_COOKIE,               "Cookie" },
    { FN_ENCODING_VERSION,     "Encoding-Version" },
    { FN_PROFILE_WARNING14,    "Profile-Warning (encoding 1.4)" },
    { FN_CONTENT_DISPOSITION14,"Content-Disposition (encoding 1.4)" },
    { FN_X_WAP_SECURITY,       "X-WAP-Security" },
    { FN_CACHE_CONTROL14,      "Cache-Control (encoding 1.4)" },
    /* encoding-version 1.5 */
    { FN_EXPECT15,             "Expect (encoding 1.5)" },
    { FN_X_WAP_LOC_INVOCATION, "X-Wap-Loc-Invocation" },
    { FN_X_WAP_LOC_DELIVERY,   "X-Wap-Loc-Delivery" },
    { 0,                       NULL }
};


#define MM_QUOTE                0x7F    /* Quoted string        */
#define MMS_CONTENT_TYPE        0x3E    /* WINA-value for mms-message   */


#define is_short_integer(x)         ( (x) & 0x80 )
#define is_long_integer(x)          ( (x) <= 30 )
#define is_date_value(x)            is_long_integer(x)
#define is_integer_value(x)         (is_short_integer(x) || is_long_integer(x))
#define is_delta_seconds_value(x)   is_integer_value(x)
/* Text string == *TEXT 0x00, thus also an empty string matches the rule! */
#define is_text_string(x)           ( ((x) == 0) || ( ((x) >= 32) && ((x) <= 127)) )
#define is_quoted_string(x)         ( (x) == 0x22 ) /* " */
#define is_token_text(x)            is_text_string(x)
#define is_text_value(x)            is_text_string(x)
#define is_uri_value(x)             is_text_string(x)


static const char *
val_to_str(const uint8_t val, const val_string list[])
{
    int i = 0;

    while (list[i].name) {
        if (list[i].val == val) {
            return list[i].name;
        }

        i++;
    }

    return "Unknown Header";
}


#define POS_MOVE(cur, step)                 \
do {                                        \
    /* step may be a funciton */            \
    /* Dont call it twice */                \
    uint32_t tmp_step = step;               \
    if (cur + tmp_step <= end) {            \
        cur += tmp_step;                    \
    } else {                                \
        SCReturnInt(-1);                    \
    }                                       \
} while(0)

#define decode_uintvar(cur, value)          \
do {                                        \
    uint8_t val = 0;                        \
    const uint8_t *begin = cur;             \
                                            \
    val = *cur;                             \
    POS_MOVE(cur, 1);                       \
                                            \
    while(val & 0x80) {                     \
        value |= (val & 0x7F);              \
        value <<= 7;   /* 7 bits */         \
        val = *cur;                         \
        POS_MOVE(cur, 1);                   \
    }                                       \
                                            \
    value |= val; /* last 7 bits */         \
                                            \
    SCLogInfo("value is %lu,"               \
            "bytes_count is %d",            \
            value, (int)(cur-begin));       \
} while(0)

#define decode_int(cur, val)                                       \
do {                                                               \
    int bytes_count = 0;                                           \
                                                                   \
    if (*cur & 0x80) {                                             \
        /* value is *cur & 0x&F */                                 \
        val = *cur & 0x7F;                                         \
        POS_MOVE(cur, 1);                                          \
    } else {                                                       \
        /* Get bytes count first*/                                 \
        bytes_count = *cur;                                        \
        POS_MOVE(cur, 1);                                          \
                                                                   \
        if (bytes_count == 1) {                                    \
            val = *cur;                                            \
        } else if (bytes_count == 2) {                             \
            val = (uint16_t) *((const uint8_t *)cur+0)<<8 |        \
                 (uint16_t) *((const uint8_t *)cur+1)<<0;          \
        } else if (bytes_count == 3) {                             \
            val = (uint32_t) *((const uint8_t *)cur+0)<<16|        \
                  (uint32_t) *((const uint8_t *)cur+1)<<8 |        \
                  (uint32_t) *((const uint8_t *)cur+2)<<0;         \
        } else if (bytes_count == 4) {                             \
            val = (uint32_t) *((const uint8_t *)cur+0)<<24 |       \
                  (uint32_t) *((const uint8_t *)cur+1)<<16 |       \
                  (uint32_t) *((const uint8_t *)cur+2)<<8  |       \
                  (uint32_t) *((const uint8_t *)cur+3)<<0;         \
        }                                                          \
                                                                   \
        POS_MOVE(cur, bytes_count);                                \
    }                                                              \
} while (0)

#define decode_long_int(cur)                                       \
do {                                                               \
    int bytes_count = 0;                                           \
                                                                   \
    /* Get bytes count first*/                                     \
    bytes_count = *cur;                                            \
                                                                   \
    POS_MOVE(cur, 1);                                              \
                                                                   \
    POS_MOVE(cur, bytes_count);                                    \
} while (0)

#define decode_text_string(cur)                                    \
do {                                                               \
    /* TODO: It may overflow if there isn't '\0' at the end */     \
    SCLogInfo("Text value is %s", cur);                            \
                                                                   \
    while (*cur != 0) {                                            \
        POS_MOVE(cur, 1);                                          \
    }                                                              \
                                                                   \
    /* Jump to the beginning of the next area */                   \
    POS_MOVE(cur, 1);                                              \
} while (0)


#define decode_encoded_string(cur)                                 \
do {                                                               \
    uint64_t len = 0;                                              \
                                                                   \
    if (*cur < 0x20) {                                             \
        if (*cur < 0x1F) {                                         \
            len = *cur;                                            \
            /* There is 1 byte value */                            \
            POS_MOVE(cur, 1);                                      \
        } else { /*31; It is uintvar */                            \
            POS_MOVE(cur, 1);                                      \
            decode_uintvar(cur, len);                              \
        }                                                          \
                                                                   \
        SCLogInfo("string is %s", cur);                            \
                                                                   \
        POS_MOVE(cur, len);                                        \
                                                                   \
    } else { /* text string */                                     \
        decode_text_string(cur);                                   \
    }                                                              \
} while (0)

/* General form:
 *    ( no-cache | private ) 1*( Field-name )
 *  | ( max-age | max-stale | min-fresh | s-maxage) Delta-seconds-value
 *  | Token-text ( Integer-value | Text-value )
 * Where:
 *  Field-name = Short-integer | Token-text
 */
#define                                                           \
decode_value_with_length(cur)                                     \
do {                                                              \
    uint64_t len = 0;                                             \
                                                                  \
    if (*pos == 0x1F) { /* Value Length = uintvar */              \
        POS_MOVE(pos, 1);                                         \
                                                                  \
        decode_uintvar(pos, len);                                 \
    } else {                                                      \
        /* Short length followed by Len data octets */            \
        len = *pos;                                               \
                                                                  \
        POS_MOVE(pos, 1); /* There is 1 byte value */             \
    }                                                             \
} while (0)


/* MM_CTYPE_HDR is encoded with WSP format
 * Content-type-value =
 *    Short-integer
 *  | Extension-media
 *  | ( Value-length ( Extension-media | Integer-value ) *( Parameter ) )
 */
static int64_t
decode_mm_content_type(const uint8_t *pos, uint32_t header_len, bool *is_text)
{
    const uint8_t *begin = pos;
    const uint8_t *end = pos + header_len;
    uint32_t ctype = 0;

    uint64_t len = 0;

    *is_text = false;

    if (*pos & 0x80) { /* Well-known value */
        ctype = *pos & 0x7F;

        SCLogInfo("Content-Type is 0x%x %s", *pos & 0x7F, val_to_str(*pos & 0x7F, mm_content_types));

        if (ctype > 0 && ctype < 0x0B) {
            *is_text = true;
        }

        POS_MOVE(pos, 1);
    } else if ((*pos == 0) || (*pos >= 0x20)) { /* Textual value */
        decode_text_string(pos);
    } else { /* pos points to 1st byte of length field */
        if (*pos == 0x1F) { /* Value Length = uintvar */
            POS_MOVE(pos, 1);

            decode_uintvar(pos, len);
        } else {
            len = *pos;

            POS_MOVE(pos, 1); /* There is 1 byte value */
        }

        /* Only decode CType value but don't move pos */
        if (is_text_string(*pos)) {
            SCLogInfo("Content-Type is %s", pos);
        } else if (is_integer_value(*pos)) {
            const uint8_t *tmp_pos = pos;
            /* We only think well-known(int) type is multipart and ignore text string */
            decode_int(tmp_pos, ctype);

            SCLogInfo("Content-Type is %s", val_to_str(ctype, mm_content_types));
            if (ctype > 0 && ctype < 0x0B) {
                *is_text = true;
            }

        } else {
            /* Malformat */
            SCReturnInt(-1);
        }

        /*
         * Move pos accordint to len,
         * ignore all parameters.
         * The following is Data
         */
        POS_MOVE(pos, len);
    }

    return pos - begin;
}

static int
decode_mm_headers(uint8_t *pos, uint32_t data_len, char **filename)
{
    const uint8_t *begin = pos;
    const uint8_t *end = pos + data_len;
    uint64_t len = 0;

    int file_flag = 0;
    size_t filename_len = 0;

    while (pos - begin < data_len) {
        if (*pos & 0x80) { /* Well-known WSP header encoding */
            SCLogInfo("MIME Header is %d, %s", *pos & 0x7F, val_to_str(*pos & 0x7F, vals_field_names));

            /* We only parse the detail of Content-Disposition becasue we want to get filename */
            if ((*pos & 0x7F) == FN_CONTENT_DISPOSITION) {
                SCLogInfo("Content-Disposition is found");
                file_flag = 1;
            } else {
                file_flag = 0;
            }

            POS_MOVE(pos, 1);

            if (*pos & 0x80) { /* Well-known value */
                POS_MOVE(pos, 1);
            } else if (is_text_string(*pos)) { /* Text */
                decode_text_string(pos);
            } else { /* General form with length */
                if (*pos == 0x1F) { /* 31: Value length in uintvar */
                    POS_MOVE(pos, 1);

                    decode_uintvar(pos, len);

                } else { /* Value length in octet */
                    len = *pos;

                    POS_MOVE(pos, 1); /* There is 1 byte value */
                }

                /* Only decode value for debug but don't move pos */
                if (is_text_string(*pos)) {
                    SCLogInfo("Value is %s", pos);
                } else if (is_integer_value(*pos)) {
                    uint32_t value = 0;
                    uint8_t *tmp_pos = pos;

                    decode_int(tmp_pos, value);

                    SCLogInfo("value is %u", value); //val_to_str(ctype, mm_content_types));

                    /*
                     * Content-disposition-value = Value-length ( Disposition ) *( Parameter )
                     *  Disposition = Form-data | Attachment | Inline | Token-text
                     *  Form-data = 0x80
                     *  Attachment = 0x81
                     *  Inline = 0x82
                     * We handle this as:
                     *  Value-length ( Short-integer | Text-string ) *( Parameter )
                     */

                    /* The following is parameter */
                    if (file_flag == 1) {
                        if (*tmp_pos & 0x80) { /* Well-known value */
                            SCLogInfo("para is %u %s", *tmp_pos & 0x7F, val_to_str(*tmp_pos & 0x7F, parameter_type));
                        }
                        if (((*tmp_pos) & 0x7F) == 0x06 && filename) {
                            POS_MOVE(tmp_pos, 1);
                            (void)HTTPParseContentDispositionHeader((uint8_t *)"", 0,
                                          tmp_pos, len-1, (uint8_t **)filename, &filename_len);
                        } else {
                            POS_MOVE(tmp_pos, 1);
                        }

                        if (is_integer_value(*tmp_pos)) {
                            decode_int(tmp_pos, value);
                        }
                        if (*tmp_pos & 0x80) { /* Well-known value */
                            POS_MOVE(tmp_pos, 1);
                        } else if (is_text_string(*tmp_pos)) { /* Text */
                            decode_text_string(tmp_pos);
                        } else { /* General form with length */
                            if (*tmp_pos == 0x1F) { /* 31: Value length in uintvar */
                                POS_MOVE(tmp_pos, 1);

                                decode_uintvar(tmp_pos, len);
                            }
                        }
                    }
                } else {
                    /* Malformat */
                    SCReturnInt(-1);
                }

                /*
                 * Move pos accordint to len,
                 * ignore all parameters.
                 * The following is Data
                 */
                POS_MOVE(pos, len);
            }
        } else { /* Literal WSP header encoding */
            decode_text_string(pos);
        }
    }

    return pos - begin;
}

/**
 *  \brief Open the file with "filename" and pass the first chunk
 *         of data if any.
 *
 *  \param s http state
 *  \param filename name of the file
 *  \param filename_len length of the name
 *  \param data data chunk (if any)
 *  \param data_len length of the data portion
 *  \param direction flow direction
 *
 *  \retval  0 ok
 *  \retval -1 error
 *  \retval -2 not handling files on this flow
 */
static int HTPMMSFileOpen(HtpState *s, const char *filename, uint16_t filename_len,
                 const uint8_t *data, uint32_t data_len,
                 uint64_t txid, uint8_t direction)
{
    int retval = 0;
    uint16_t flags = 0;
    FileContainer *files = NULL;
    const StreamingBufferConfig *sbcfg = NULL;

    SCLogDebug("data %p data_len %"PRIu32, data, data_len);

    if (s == NULL) {
        SCReturnInt(-1);
    }

    if (direction & STREAM_TOCLIENT) {
        if (s->mms_files_tc == NULL) {
            s->mms_files_tc = FileContainerAlloc();
            if (s->mms_files_tc == NULL) {
                retval = -1;
                goto end;
            }
        }

        files = s->mms_files_tc;

        flags = FileFlowToFlags(s->f, STREAM_TOCLIENT);

        if ((s->flags & HTP_MMS_FLAG_STORE_FILES_TS) ||
                ((s->flags & HTP_MMS_FLAG_STORE_FILES_TX_TS) && txid == s->store_tx_id)) {
            flags |= FILE_STORE;
            flags &= ~FILE_NOSTORE;
        } else if (!(flags & FILE_STORE) && (s->f->file_flags & FLOWFILE_NO_STORE_TC)) {
            flags |= FILE_NOSTORE;
        }

        sbcfg = &s->cfg->response.sbcfg;

    } else {
        if (s->mms_files_ts == NULL) {
            s->mms_files_ts = FileContainerAlloc();
            if (s->mms_files_ts == NULL) {
                retval = -1;
                goto end;
            }
        }

        files = s->mms_files_ts;

        flags = FileFlowToFlags(s->f, STREAM_TOSERVER);
        if ((s->flags & HTP_MMS_FLAG_STORE_FILES_TC) ||
                ((s->flags & HTP_MMS_FLAG_STORE_FILES_TX_TC) && txid == s->store_tx_id)) {
            flags |= FILE_STORE;
            flags &= ~FILE_NOSTORE;
        } else if (!(flags & FILE_STORE) && (s->f->file_flags & FLOWFILE_NO_STORE_TS)) {
            flags |= FILE_NOSTORE;
        }

        sbcfg = &s->cfg->request.sbcfg;
    }

    if (FileOpenFileWithId(files, sbcfg, s->file_track_id++,
                (uint8_t *)filename, filename_len,
                data, data_len, flags) != 0)
    {
        retval = -1;
    }

    FileSetTx(files->tail, txid);

end:
    SCReturnInt(retval);
}

/**
 *  \brief Close the file in the flow
 *
 *  \param s http state
 *  \param data data chunk if any
 *  \param data_len length of the data portion
 *  \param flags flags to indicate events
 *  \param direction flow direction
 *
 *  Currently on the FLOW_FILE_TRUNCATED flag is implemented, indicating
 *  that the file isn't complete but we're stopping storing it.
 *
 *  \retval 0 ok
 *  \retval -1 error
 *  \retval -2 not storing files on this flow/tx
 */
int HTPMMSFileClose(HtpState *s, const uint8_t *data, uint32_t data_len,
        uint8_t flags, uint8_t direction)
{
    SCEnter();

    int retval = 0;
    int result = 0;
    FileContainer *files = NULL;

    if (s == NULL) {
        SCReturnInt(-1);
    }

    if (direction & STREAM_TOCLIENT) {
        files = s->mms_files_tc;
    } else {
        files = s->mms_files_ts;
    }

    if (files == NULL) {
        retval = -1;
        goto end;
    }

    result = FileCloseFile(files, data, data_len, flags);
    if (result == -1) {
        retval = -1;
    } else if (result == -2) {
        retval = -2;
    }

end:
    SCReturnInt(retval);
}

/**
 *  \brief Store a chunk of data in the flow
 *
 *  \param s http state
 *  \param data data chunk (if any)
 *  \param data_len length of the data portion
 *  \param direction flow direction
 *
 *  \retval 0 ok
 *  \retval -1 error
 *  \retval -2 file doesn't need storing
 */
static int HTPMMSFileStoreChunk(HtpState *s, const uint8_t *data, uint32_t data_len,
        uint8_t direction)
{
    SCEnter();

    int retval = 0;
    int result = 0;
    FileContainer *files = NULL;

    if (s == NULL) {
        SCReturnInt(-1);
    }

    if (direction & STREAM_TOCLIENT) {
        files = s->mms_files_tc;
    } else {
        files = s->mms_files_ts;
    }

    if (files == NULL) {
        SCLogDebug("no files in state");
        retval = -1;
        goto end;
    }

    result = FileAppendData(files, data, data_len);
    if (result == -1) {
        SCLogDebug("appending data failed");
        retval = -1;
    } else if (result == -2) {
        retval = -2;
    }

end:
    SCReturnInt(retval);
}

static int
decode_mm_multi_data(HtpState *hstate, HtpTxUserData *htud, uint8_t *pos, int len, struct mms_t *mms,
                              uint8_t direction)
{
    int ret = 0;
    const uint8_t *begin = pos;
    const uint8_t *end = pos + len;
    uint64_t header_len = 0;
    uint64_t data_len = 0;
    char *filename = NULL;
    int64_t header_parsed_len = 0;
    uint64_t left_len = len;
    int result = 0;
    uint64_t id = 0;
    uint8_t flags;
    bool is_text = false;

    decode_uintvar(pos, (mms->entry_num));

    SCLogInfo("There are %lu entries in this body", mms->entry_num);

    while (mms->entry_num) {
        header_len = 0;
        data_len = 0;
        decode_uintvar(pos, header_len);

        decode_uintvar(pos, data_len);

        SCLogInfo("header len is %lu, data len is %lu", header_len, data_len);

        if (htud->tcflags & HTP_MMS_FILENAME_SET) {
             SCLogDebug("closing file that was being stored");
             (void)HTPMMSFileClose(hstate, NULL, 0, 0, direction);
             htud->tcflags &= ~HTP_MMS_FILENAME_SET;
        }

        header_parsed_len = decode_mm_content_type(pos, header_len, &is_text);

        if (header_parsed_len < 0) {
            SCReturnInt(-1);
        }

        if ((uint64_t) header_parsed_len < header_len) {
            SCLogInfo("parsed len is %ld, total len is %lu", header_parsed_len, header_len);

            ret = decode_mm_headers(pos + header_parsed_len, header_len-header_parsed_len, &filename);
            if (ret < 0) {
                SCReturnInt(-1);
            }
        } else {
            SCLogInfo("All headers are parsed");
        }

        /* We directly jump according to the header len though we parsed header details */
        POS_MOVE(pos, header_len);
        left_len = len - (pos - begin);

        if (!is_text) {
            if (direction & STREAM_TOCLIENT) {
                flags = htud->tcflags;
            } else {
                flags = htud->tsflags;
            }
            if (!(flags & HTP_MMS_FILENAME_SET)) {
                if (direction == STREAM_TOSERVER) {
                    id = HtpGetActiveRequestTxID(hstate);
                } else {
                    id = HtpGetActiveResponseTxID(hstate);
                }

                if (filename) {
                    result = HTPMMSFileOpen(hstate, filename, strlen(filename), pos,
                                         data_len>left_len ? left_len : data_len,
                                         id, direction);
                } else {
                    result = HTPMMSFileOpen(hstate, "UnknownFile", 11, pos,
                                         data_len>left_len ? left_len : data_len,
                                         id, direction);
                }

                if (result == -1) {
                } else if (result == -2) {
                    flags |= HTP_MMS_DONTSTORE;
                } else {
                    HtpFlagDetectStateNewFile(htud, direction);
                    flags |= HTP_MMS_FILENAME_SET;
                    flags &= ~HTP_MMS_DONTSTORE;
                }
            }
            if (direction == STREAM_TOCLIENT) {
                htud->tcflags = flags;
            } else {
                htud->tsflags = flags;
            }
        }

        /* Following is true data which length is data_len */


        if (data_len <= left_len) {

            POS_MOVE(pos, data_len);
            mms->entry_num--;
            if (htud != NULL) {
                if (htud->tcflags & HTP_MMS_FILENAME_SET) {
                    SCLogDebug("closing file that was being stored");
                    (void)HTPMMSFileClose(hstate, NULL, 0, 0, direction);
                    htud->tcflags &= ~HTP_MMS_FILENAME_SET;
                }
            }
            left_len = len - (pos - begin);
        } else {

            mms->data_left_len = data_len - left_len;

            POS_MOVE(pos, left_len);

            left_len = 0;
            return pos - begin;
        }
    }

    return pos - begin;
}

/*
 * We are only interested in PDU_M_RETRIEVE_CONF and PDU_M_SEND_REQ,
 * PDU_M_MBOX_DELETE_CONF message has special format.
 */
int HTPHandleMMSData(HtpState *hstate, HtpTxUserData *htud, uint8_t *data, uint32_t data_len,
                            uint8_t direction)
{
    uint8_t *pos = data;
    struct mms_t *mms = &(hstate->mms);
    uint8_t *end = data + data_len;
    uint8_t data_flag = 0;
    uint8_t data_interest_flag = 0;
    int result = 0;

    if (hstate == NULL) {
        SCReturnInt(-1);
    }

    if (!pos) {
        SCLogInfo("There isn't MMS data in this packet\n");
        SCReturnInt(0);
    }

    if (mms->data_left_len) {
        SCLogInfo("left multi part is %lu, left data len is %lu, data in packet len is %u", mms->entry_num, mms->data_left_len, data_len);

        if (data_len < mms->data_left_len) {
            if (!(htud->tsflags & HTP_MMS_DONTSTORE)) {
                result = HTPMMSFileStoreChunk(hstate, pos, data_len, direction);
                if (result == -1) {
                    SCReturnInt(0);
                } else if (result == -2) {
                    /* we know for sure we're not storing the file */
                    htud->tsflags |= HTP_MMS_DONTSTORE;
                }
            }

            mms->data_left_len -= data_len;

            return 0;
        } else {
            int parsed_len = mms->data_left_len;
            if (parsed_len && (!(htud->tsflags & HTP_MMS_DONTSTORE))) {
                result = HTPMMSFileStoreChunk(hstate, pos, parsed_len, direction);
                if (result == -1) {
                    SCReturnInt(0);
                } else if (result == -2) {
                    /* we know for sure we're not storing the file */
                    htud->tsflags |= HTP_MMS_DONTSTORE;
                }
                if (htud != NULL) {
                    if (htud->tcflags & HTP_MMS_FILENAME_SET) {
                        SCLogDebug("closing file that was being stored");
                        (void)HTPMMSFileClose(hstate, NULL, 0, 0, direction);
                        htud->tcflags &= ~HTP_MMS_FILENAME_SET;
                    }
                }
            }
            pos += mms->data_left_len;
            mms->data_left_len = 0;
            mms->entry_num--;

            if (mms->entry_num) {
                decode_mm_multi_data(hstate, htud, pos, data_len - parsed_len, mms, direction);
            }

            SCReturnInt(0);
        }
    } else {
        SCLogInfo("Start parsing MMS message");
    }

    /*
     * Sanity check, the beginning headers must be MM_MTYPE_HDR, MM_TID_HDR, MM_VERSION_HDR in order
     * Only check MM_MTYPE_HDR now.
     */
    if (*pos == MM_MTYPE_HDR) { /* uint8 */
        SCLogInfo("A MMS message is captured");
    } else {
        SCReturnInt(0);
    }

    while ((end - pos <= data_len) && !data_flag) { /* Don't think END data cold be the last header */
        SCLogInfo("MMS Header is 0x%x %s", *pos, val_to_str(*pos, mm_header));
        switch (*pos) {
            case MM_MTYPE_HDR: /* uint8 */
                POS_MOVE(pos, 1);

                if (*pos != PDU_M_RETRIEVE_CONF && *pos != PDU_M_SEND_REQ) {
                    SCLogInfo("We are only interested in m-retrieve-conf(0x84) \
                               or m-send-req(0x80), ignore this message %u\n", *pos);
                    SCReturnInt(0);
                }

                POS_MOVE(pos, 1);

                break;
            case MM_TID_HDR: /* Text-string */
                POS_MOVE(pos, 1);

                decode_text_string(pos);

                break;

            case MM_VERSION_HDR: /* nibble-Major/nibble-minor */
                POS_MOVE(pos, 1);

                SCLogInfo("Ver HDR is %u.%u", (*pos & 0x70)>>4, *pos & 0x0F);

                POS_MOVE(pos, 1);

                break;

            case MM_CTYPE_HDR: /* It must be the last header and data is following it */
                /* MM_CTYPE_HDR is encoded with WSP format
                 * Content-type-value =
                 *    Short-integer
                 *  | Extension-media
                 *  | ( Value-length ( Extension-media | Integer-value ) *( Parameter ) )
                 */
                POS_MOVE(pos, 1);

                if (*pos & 0x80) { /* Well-known value */
                    SCLogInfo("Content-Type is %s", val_to_str(*pos & 0x7F, mm_content_types));
                    POS_MOVE(pos, 1);
                } else if ((*pos == 0) || (*pos >= 0x20)) { /* Textual value */
                    decode_text_string(pos);
                } else { /* pos points to 1st byte of length field */
                    uint64_t len = 0;
                    if (*pos == 0x1F) { /* Value Length = uintvar */
                        POS_MOVE(pos, 1);

                        decode_uintvar(pos, len);
                    } else {
                        len = *pos;

                        POS_MOVE(pos, 1); /* There is 1 byte value */
                    }

                    /* Only decode CType value but don't move pos */
                    if (is_text_string(*pos)) {
                        SCLogInfo("Content-Type is %s", pos);
                    } else if (is_integer_value(*pos)) {
                        uint32_t ctype = 0;
                        const uint8_t *tmp_pos = pos;
                        /* We only think well-known(int) type is multipart and ignore text string */
                        decode_int(tmp_pos, ctype);

                        SCLogInfo("Content-Type is %s", val_to_str(ctype, mm_content_types));

                        /* We are only interested in these content-types */
                        if (ctype == 0x22 || ctype == 0x23 || ctype == 0x24 ||
                                ctype == 0x25 || ctype == 0x26 || ctype == 0x33) {
                            data_interest_flag = 1;
                        }

                    } else {
                        /* Malformat */
                        SCReturnInt(-1);
                    }

                    /*
                     * Move pos accordint to len,
                     * ignore all parameters.
                     * The following is Data
                     */
                    POS_MOVE(pos, len);
                }

                data_flag = 1;

                break;

            case MM_BCC_HDR:  /* Encoded-string-value */
            case MM_CC_HDR:   /* Encoded-string-value */
            case MM_TO_HDR:
                {
                    uint64_t len = 0;
                    uint64_t i = 0;
                    int    cnt =  htud->mmse_info.msg_to_cnt;
                    char **msg_to = htud->mmse_info.msg_to;

                    POS_MOVE(pos, 1);

                    msg_to = HTPRealloc(msg_to, sizeof(char*) * cnt, sizeof(char*) * (cnt + 1));
                    if (!msg_to) {
                        break;
                    }

                    if (*pos < 0x20) {
                        if (*pos < 0x1F) {
                            len = *pos;
                            /* There is 1 byte value */
                            POS_MOVE(pos, 1);
                        } else { /*31; It is uintvar */
                            POS_MOVE(pos, 1);
                            decode_uintvar(pos, len);
                        }

                        SCLogInfo("string is %s", pos);

                        msg_to[cnt] = (char*)malloc(len);
                        while ((i < len) && (pos[i] != 0)) {
                            msg_to[cnt][i] = pos[i];
                            i++;
                        }
                        msg_to[cnt][i] = '\0';

                    } else { /* text string */
                        SCLogInfo("Text value is %s", pos);
                        while (pos[i] != 0) {
                            i++;
                        }
                        len = i + 1;

                        if (i) {
                            msg_to[cnt] = (char*)malloc(len);

                            for (i = 0; i < len; i++) {

                                msg_to[cnt][i] = pos[i];
                            }
                        }
                    }
                    htud->mmse_info.msg_to = msg_to;
                    htud->mmse_info.msg_to_cnt++;

                    POS_MOVE(pos, len);
                    break;
                }

            case MM_CLOCATION_HDR: /* uri */
                POS_MOVE(pos, 1);

                /* if pdu type is PDU_M_MBOX_DELETE_CONF,
                 * It has different format.
                 * Ignore it based on current logic
                 * */
                decode_text_string(pos);

                break;
            case MM_DATE_HDR:      /* Long-integer */
                POS_MOVE(pos, 1);

                decode_long_int(pos);

                break;

            case MM_DTIME_HDR:  /* Value-length(Absolute-token Date-value | Relative-token Delta-seconds-value) */
            case MM_EXPIRY_HDR: /* Value-length(Absolute-token Date-value | Relative-token Delta-seconds-value) */
                {
                    uint64_t len = 0;

                    POS_MOVE(pos, 1);

                    if (*pos < 0x1F) { /* uint8 */
                        POS_MOVE(pos, 1);
                    } else {
                        POS_MOVE(pos, 1);
                        decode_uintvar(pos, len);
                    }

                    /* Long int */
                    POS_MOVE(pos, 1);

                    decode_long_int(pos);
                }

                break;

            case MM_FROM_HDR: /* Value-length(Address-present-token Encoded-string-value | Insert-address-token) */
                {
                    uint64_t len = 0;
                    uint64_t tmp_len = 0;
                    uint64_t i = 0;
                    char    *msg_from = NULL;

                    POS_MOVE(pos, 1);

                    if (*pos < 0x1F) { /* uint8 */
                        len = *pos;
                        POS_MOVE(pos, 1);
                    } else {
                        decode_uintvar(pos, len);
                    }

                    SCLogInfo("From header value length is %lu", len);

                    uint8_t *tmp_pos = pos;

                    if (*tmp_pos != 0x81) { /* <insert address> ; Don't print */
                        POS_MOVE(tmp_pos, 1);
                        if (*tmp_pos < 0x20) {
                            if (*tmp_pos < 0x1F) {
                                tmp_len = *tmp_pos;
                                /* There is 1 byte value */
                                POS_MOVE(tmp_pos, 1);
                            } else { /*31; It is uintvar */
                                POS_MOVE(tmp_pos, 1);
                                decode_uintvar(tmp_pos, tmp_len);
                            }
                            if (!msg_from) {
                                msg_from = (char*)malloc(tmp_len);
                                while ((i < tmp_len) && (tmp_pos[i] != 0)) {
                                    msg_from[i] = tmp_pos[i];
                                    i++;
                                }
                                msg_from[i] = '\0';
                                SCLogInfo("string is %s", tmp_pos);
                            }

                        } else { /* text string */
                            SCLogInfo("Text value is %s", tmp_pos);

                            while (tmp_pos[i] != 0) {
                                i++;
                            }
                            tmp_len = i + 1;

                            if (!msg_from && i) {
                                msg_from = (char*)malloc(tmp_len);

                                for (i = 0; i < tmp_len; i++) {

                                    msg_from[i] = tmp_pos[i];
                                }
                            }

                            htud->mmse_info.msg_from = msg_from;
                        }
                    }
                    POS_MOVE(pos, len);

                    break;
                }
            case MM_MCLASS_HDR: /* Class-identifier|Text-string */
                POS_MOVE(pos, 1);

                if (*pos & 0x80) { /* uint8 */
                    POS_MOVE(pos, 1);
                } else {
                    decode_text_string(pos);
                }

                break;

            case MM_MID_HDR:        /* text string */
                POS_MOVE(pos, 1);

                decode_text_string(pos);

                break;

            case MM_MSIZE_HDR:      /* long int */
                POS_MOVE(pos, 1);

                decode_long_int(pos);

                break;

            case MM_DREPORT_HDR:    /* Yes|No */
            case MM_PRIORITY_HDR:   /* Low|Normal|High */
            case MM_RREPLY_HDR:     /* Yes|No */
            case MM_RALLOWED_HDR:   /* Yes|No */
            case MM_RSTATUS_HDR:
            case MM_SVISIBILITY_HDR: /* Hide|Show */
            case MM_STATUS_HDR:
                POS_MOVE(pos, 1);

                POS_MOVE(pos, 1);

                break;

            case MM_RTEXT_HDR:      /* Encoded-string-value */
                POS_MOVE(pos, 1);

                decode_encoded_string(pos);

                break;

            case MM_SUBJECT_HDR: /* Encoded-string-value */
                POS_MOVE(pos, 1);

                decode_encoded_string(pos);

                break;

            case MM_RETRIEVE_TEXT_HDR: /* Encoded-string-value; Ignore PDU_M_MBOX_DELETE_CONF which has different format */
                POS_MOVE(pos, 1);

                decode_encoded_string(pos);

                break;

            case MM_RETRIEVE_STATUS_HDR:  /* Well-known-value uint8 */
            case MM_READ_STATUS_HDR:      /* Well-known-value uint8 */
            case MM_REPLY_CHARGING_HDR:   /* Well-known-value uint8 */
                POS_MOVE(pos, 1);

                POS_MOVE(pos, 1);

                break;

            case MM_REPLY_CHARGING_DEADLINE_HDR: /* Well-known-value */  /* Value-length(Absolute-token Date-value | Relative-token Delta-seconds-value) */
                {
                    uint64_t len = 0;

                    POS_MOVE(pos, 1);

                    if (*pos < 0x1F) { /* uint8 */
                        POS_MOVE(pos, 1);
                    } else {
                        POS_MOVE(pos, 1);
                        decode_uintvar(pos, len);
                    }

                    /* Long int */
                    POS_MOVE(pos, 1);
                    decode_long_int(pos);
                }

                break;

            case MM_REPLY_CHARGING_ID_HDR: /* Text-string */
                POS_MOVE(pos, 1);

                decode_text_string(pos);

                break;

            case MM_REPLY_CHARGING_SIZE_HDR:  /* Long-integer */
                POS_MOVE(pos, 1);

                decode_long_int(pos);

                break;

            case MM_PREV_SENT_BY_HDR: /* Value-length Integer-value Encoded-string-value */
                {
                    uint64_t len = 0;

                    POS_MOVE(pos, 1);

                    if (*pos < 0x1F) { /* uint8 */
                        len = *pos;
                        POS_MOVE(pos, 1);
                    } else {
                        decode_uintvar(pos, len);
                    }

                    {
                        /* Only for debug; No jump offset */
                        const uint8_t *tmp_pos = pos;
                        uint32_t val = 0;
                        decode_int(tmp_pos, val);

                        SCLogInfo("value is %u", val);

                        decode_encoded_string(tmp_pos);
                    }


                    /* We don't care about the value */
                    POS_MOVE(pos, len);
                }

                break;

            case MM_PREV_SENT_DATE_HDR: /* Value-Length Forwarded-count-value Date-value */
                {
                    uint64_t len = 0;

                    POS_MOVE(pos, 1);

                    if (*pos < 0x1F) { /* uint8 */
                        len = *pos;
                        POS_MOVE(pos, 1);
                    } else {
                        decode_uintvar(pos, len);
                    }

                    /* We don't care about the value */
                    POS_MOVE(pos, len);
                }

                break;

            default:
                {
                    POS_MOVE(pos, 1);

                    if (*pos & 0x80) { /* Well-known WSP header encoding */
                        SCLogInfo("Received %s", val_to_str(*pos, mm_header));

                        POS_MOVE(pos, 1);

                        if (*pos & 0x80) { /* Well-known value */
                            POS_MOVE(pos, 1);
                        } else if (*pos == 0 || *pos >= 0x20) { /* Text */
                            decode_text_string(pos);
                        } else { /* General form with length */
                            if (*pos == 0x1F) { /* 31: Value length in uintvar */
                                uint64_t len = 0;

                                POS_MOVE(pos, 1);

                                decode_uintvar(pos, len);
                            } else { /* Value length in octet */
                                POS_MOVE(pos, 1);

                                POS_MOVE(pos, 1);
                            }
                        }
                    } else { /* Literal WSP header encoding */
                        decode_text_string(pos);
                    }
                }

                break;
        }
    }

    /*
     * Following is Data
     * we are only interested in multipart
     */
    if (data_flag && data_interest_flag) {
        if (hstate->flags & HTP_MMS_FLAG_STORE_FILES_TS ||
                hstate->flags & HTP_MMS_FLAG_STORE_FILES_TX_TS) {
            /* We will store file with HTTP options*/
            return decode_mm_multi_data(hstate, htud, pos, data_len - (pos - data), mms, direction);
        } else {
            return decode_mm_multi_data(hstate, htud, pos, data_len - (pos - data), mms, direction);
        }
    }

    SCReturnInt(0);
}


