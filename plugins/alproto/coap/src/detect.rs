/* Copyright (C) 2024 Open Information Security Foundation
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

// same file as rust/src/applayertemplate/detect.rs except
// TEMPLATE_START_REMOVE removed
// different paths for use statements
// keywords prefixed with coap instead of just template

use super::coap::{COAPTransaction, ALPROTO_COAP};
use std::os::raw::{c_int, c_void};
use suricata::cast_pointer;
use suricata::core::{STREAM_TOCLIENT, STREAM_TOSERVER};
use suricata::detect::{helper_keyword_register_sticky_buffer, SigTableElmtStickyBuffer};
use suricata::direction::Direction;
use suricata_sys::sys::{
    DetectEngineCtx, SCDetectBufferSetActiveList, SCDetectHelperBufferMpmRegister,
    SCDetectSignatureSetAppProto, Signature,
};

static mut G_COAP_BUFFER_BUFFER_ID: c_int = 0;

unsafe extern "C" fn coap_buffer_setup(
    de: *mut DetectEngineCtx, s: *mut Signature, _raw: *const std::os::raw::c_char,
) -> c_int {
    if SCDetectSignatureSetAppProto(s, ALPROTO_COAP) != 0 {
        return -1;
    }
    if SCDetectBufferSetActiveList(de, s, G_COAP_BUFFER_BUFFER_ID) < 0 {
        return -1;
    }
    return 0;
}

/// Get the request/response buffer for a transaction from C.
unsafe extern "C" fn coap_buffer_get(
    tx: *const c_void, flags: u8, buf: *mut *const u8, len: *mut u32,
) -> bool {
    let tx = cast_pointer!(tx, COAPTransaction);
    if flags & Direction::ToClient as u8 != 0 {
        if let Some(ref response) = tx.response {
            *len = response.len() as u32;
            *buf = response.as_ptr();
            return true;
        }
    } else if let Some(ref request) = tx.request {
        *len = request.len() as u32;
        *buf = request.as_ptr();
        return true;
    }
    return false;
}

pub(super) unsafe extern "C" fn detect_coap_register() {
    // TODO create a suricata-verify test
    // Setup a keyword structure and register it
    let kw = SigTableElmtStickyBuffer {
        name: String::from("coap.buffer"),
        desc: String::from("COAP content modifier to match on the coap buffer"),
        // TODO use the right anchor for url and write doc
        url: String::from("/rules/coap-keywords.html#buffer"),
        setup: coap_buffer_setup,
    };
    let _g_coap_buffer_kw_id = helper_keyword_register_sticky_buffer(&kw);
    G_COAP_BUFFER_BUFFER_ID = SCDetectHelperBufferMpmRegister(
        b"coap.buffer\0".as_ptr() as *const libc::c_char,
        b"coap.buffer intern description\0".as_ptr() as *const libc::c_char,
        ALPROTO_COAP,
        STREAM_TOSERVER | STREAM_TOCLIENT,
        Some(coap_buffer_get),
    );
}
