/* Copyright (C) 2018-2022 Open Information Security Foundation
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

// same file as rust/src/applayertemplate/template.rs except
// different paths for use statements
// remove TEMPLATE_START_REMOVE
// name is coap instead of template

use super::parser;
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use suricata::applayer::{
    state_get_tx_iterator, AppLayerEvent, AppLayerRegisterParser,
    AppLayerRegisterProtocolDetection, AppLayerResult, AppLayerStateData, AppLayerTxData,
    RustParser, State, StreamSlice, Transaction, APP_LAYER_PARSER_EOF_TC, APP_LAYER_PARSER_EOF_TS,
    APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
};
use suricata::conf::conf_get;
use suricata::core::{ALPROTO_UNKNOWN, IPPROTO_UDP};
use suricata::{
    build_slice, cast_pointer, export_state_data_get, export_tx_data_get, SCLogError, SCLogNotice,
};
use suricata_sys::sys::{
    AppLayerParserState, AppProto, Flow, SCAppLayerParserConfParserEnabled,
    SCAppLayerParserRegisterLogger, SCAppLayerParserStateIssetFlag,
    SCAppLayerProtoDetectConfProtoDetectionEnabled,
};

static mut COAP_MAX_TX: usize = 256;

pub(super) static mut ALPROTO_COAP: AppProto = ALPROTO_UNKNOWN;

#[derive(AppLayerEvent)]
enum COAPEvent {
    TooManyTransactions,
}

enum COAPCode {
    GET = 1,
    POST,
    PUT,
    DELETE,
}

pub(super) struct COAPTransaction {
    tx_id: u64,
    pub request: Option<String>,
    pub response: Option<String>,
    pub msg_type: Option<String>,
    pub code: u16,
    pub mid: u16,
    pub token: Option<String>,
    pub uri_path: Option<String>,
    pub uri_query: Option<String>,
    pub payload: Option<String>,
    pub options: Option<String>,

    tx_data: AppLayerTxData,
}

impl Default for COAPTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl COAPTransaction {
    pub fn new() -> COAPTransaction {
        Self {
            tx_id: 0,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }
}

impl Transaction for COAPTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
struct COAPState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<COAPTransaction>,
    request_gap: bool,
    response_gap: bool,
}

impl State<COAPTransaction> for COAPState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&COAPTransaction> {
        self.transactions.get(index)
    }
}

impl COAPState {
    pub fn new() -> Self {
        Default::default()
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&COAPTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> COAPTransaction {
        let mut tx = COAPTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut COAPTransaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.response.is_none())
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this coap, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.request_gap = false;
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, request)) => {
                    start = rem;

                    SCLogNotice!("Request: {}", request);
                    let mut tx = self.new_tx();
                    tx.request = Some(request);
                    if self.transactions.len() >= unsafe { COAP_MAX_TX } {
                        tx.tx_data
                            .set_event(COAPEvent::TooManyTransactions as u8);
                    }
                    self.transactions.push_back(tx);
                    if self.transactions.len() >= unsafe { COAP_MAX_TX } {
                        return AppLayerResult::err();
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            if probe(input).is_err() {
                // The parser now needs to decide what to do as we are not in sync.
                // For this coap, we'll just try again next time.
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with a message header, clear gap
            // state and keep parsing.
            self.response_gap = false;
        }
        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, response)) => {
                    start = rem;

                    if let Some(tx) = self.find_request() {
                        tx.tx_data.updated_tc = true;
                        tx.response = Some(response);
                        SCLogNotice!("Found response for request:");
                        SCLogNotice!("- Request: {:?}", tx.request);
                        SCLogNotice!("- Response: {:?}", tx.response);
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }

    fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

/// Probe for a valid header.
///
/// As this coap protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    let size = std::cmp::min(10, input.len());
    let (rem, prefix) = nom::bytes::complete::take(size)(input)?;
    nom::sequence::terminated(
        nom::bytes::complete::take_while1(nom::character::is_digit),
        nom::bytes::complete::tag(":"),
    )(prefix)?;
    Ok((rem, ()))
}

// C exports.

/// C entry point for a probing parser.
unsafe extern "C" fn coap_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 2 bytes.
    if input_len > 1 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return ALPROTO_COAP;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn coap_state_new(_orig_state: *mut c_void, _orig_proto: AppProto) -> *mut c_void {
    let state = COAPState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn coap_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut COAPState));
}

unsafe extern "C" fn coap_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, COAPState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn coap_parse_request(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, COAPState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_request_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_request(buf)
    }
}

unsafe extern "C" fn coap_parse_response(
    _flow: *mut Flow, state: *mut c_void, pstate: *mut AppLayerParserState,
    stream_slice: StreamSlice, _data: *const c_void,
) -> AppLayerResult {
    let _eof = SCAppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, COAPState);

    if stream_slice.is_gap() {
        // Here we have a gap signaled by the input being null, but a greater
        // than 0 input_len which provides the size of the gap.
        state.on_response_gap(stream_slice.gap_size());
        AppLayerResult::ok()
    } else {
        let buf = stream_slice.as_slice();
        state.parse_response(buf)
    }
}

unsafe extern "C" fn coap_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, COAPState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn coap_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, COAPState);
    return state.tx_id;
}

unsafe extern "C" fn coap_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, COAPTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

export_tx_data_get!(coap_get_tx_data, COAPTransaction);
export_state_data_get!(coap_get_state_data, COAPState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"coap\0";

pub(super) unsafe extern "C" fn coap_register_parser() {
    let default_port = CString::new("[5683]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(coap_probing_parser),
        probe_tc: Some(coap_probing_parser),
        min_depth: 4,
        max_depth: 16,
        state_new: coap_state_new,
        state_free: coap_state_free,
        tx_free: coap_state_tx_free,
        parse_ts: coap_parse_request,
        parse_tc: coap_parse_response,
        get_tx_count: coap_state_get_tx_count,
        get_tx: coap_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: coap_tx_get_alstate_progress,
        get_eventinfo: Some(COAPEvent::get_event_info),
        get_eventinfo_byid: Some(COAPEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(state_get_tx_iterator::<COAPState, COAPTransaction>),
        get_tx_data: coap_get_tx_data,
        get_state_data: coap_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
        get_state_id_by_name: None,
        get_state_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if SCAppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_COAP = alproto;
        if SCAppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        if let Some(val) = conf_get("app-layer.protocols.coap.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                COAP_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for coap.max-tx");
            }
        }
        SCAppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_COAP);
        SCLogNotice!("Rust coap parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for COAP.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_probe() {
        assert!(probe(b"1").is_err());
        assert!(probe(b"1:").is_ok());
        assert!(probe(b"123456789:").is_ok());
        assert!(probe(b"0123456789:").is_err());
    }

    #[test]
    fn test_incomplete() {
        let mut state = COAPState::new();
        let buf = b"5:Hello3:bye";

        let r = state.parse_request(&buf[0..0]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );

        let r = state.parse_request(&buf[0..1]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 0,
                needed: 2
            }
        );

        let r = state.parse_request(&buf[0..2]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 0,
                needed: 3
            }
        );

        // This is the first message and only the first message.
        let r = state.parse_request(&buf[0..7]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );

        // The first message and a portion of the second.
        let r = state.parse_request(&buf[0..9]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 7,
                needed: 3
            }
        );
    }
}
