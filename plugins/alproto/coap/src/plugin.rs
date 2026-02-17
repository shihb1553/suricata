use super::coap::coap_register_parser;
use crate::detect::detect_coap_register;
use crate::log::coap_logger_log;
use std::ffi::CString;
use suricata::{SCLogError, SCLogNotice};
use suricata_sys::sys::{
    SCAppLayerPlugin, SCOutputJsonLogDirection, SCPlugin, SCPluginRegisterAppLayer, SC_API_VERSION,
    SC_PACKAGE_VERSION,
};

extern "C" fn coap_plugin_init() {
    suricata::plugin::init();
    SCLogNotice!("Initializing coap plugin");
    let plugin = SCAppLayerPlugin {
        name: b"coap\0".as_ptr() as *const libc::c_char,
        logname: b"JsonCOAPLog\0".as_ptr() as *const libc::c_char,
        confname: b"eve-log.coap\0".as_ptr() as *const libc::c_char,
        dir: SCOutputJsonLogDirection::LOG_DIR_PACKET as u8,
        Register: Some(coap_register_parser),
        Logger: Some(coap_logger_log),
        KeywordsRegister: Some(detect_coap_register),
    };
    unsafe {
        if SCPluginRegisterAppLayer(Box::into_raw(Box::new(plugin))) != 0 {
            SCLogError!("Failed to register coap plugin");
        }
    }
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    // leak the CString
    let plugin_version =
        CString::new(env!("CARGO_PKG_VERSION")).unwrap().into_raw() as *const libc::c_char;
    let plugin = SCPlugin {
        version: SC_API_VERSION, // api version for suricata compatibility
        suricata_version: SC_PACKAGE_VERSION.as_ptr() as *const libc::c_char,
        name: b"coap\0".as_ptr() as *const libc::c_char,
        plugin_version,
        license: b"MIT\0".as_ptr() as *const libc::c_char,
        author: b"Philippe Antoine\0".as_ptr() as *const libc::c_char,
        Init: Some(coap_plugin_init),
    };
    Box::into_raw(Box::new(plugin))
}
