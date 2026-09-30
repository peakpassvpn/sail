//! strict_route on Windows: sing-tun's firewall rules (tun_windows.go:
//! 188-367), in a dynamic session, which the system removes with the
//! handle, or the process.
//!
//! In one sublayer, on the connect layers, the higher weight first:
//!
//! | weight | layer   | condition                   | action          |
//! |--------|---------|-----------------------------|-----------------|
//! | 13     | v4, v6  | sail's own executable       | permit, hard    |
//! | 12     | v6      | (none; only with no v6 on the TUN) | block    |
//! | 11     | v4 / v6 | the TUN's interface         | permit          |
//! | 10     | v4, v6  | remote port 53              | block           |
//!
//! So DNS leaves only through the TUN, save sail's own; and with no IPv6
//! on the TUN, no IPv6 leaves at all.

use std::io;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::ip_helper::wide;

/// fwpmu.h's, a UINT32; windows-sys has it not. (Not
/// FWPM_CONDITION_IP_LOCAL_INTERFACE, the interface's UINT64 LUID.)
const FWPM_CONDITION_LOCAL_INTERFACE_INDEX: GUID =
    GUID::from_u128(0x667fd755_d695_434a_8af5_d3835a1259bc);

fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

/// The rules, while it lives.
pub(crate) struct StrictRoute {
    engine: HANDLE,
}

// SAFETY: the handle is only closed, once.
unsafe impl Send for StrictRoute {}
unsafe impl Sync for StrictRoute {}

impl Drop for StrictRoute {
    fn drop(&mut self) {
        // SAFETY: the engine opened, closed once; its dynamic objects go.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

impl StrictRoute {
    /// The rules for the TUN of interface `index`, with IPv4 and IPv6
    /// addresses as said.
    pub(crate) fn start(index: u32, ipv4: bool, ipv6: bool) -> io::Result<StrictRoute> {
        let mut name = wide("sail");
        let display = FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: std::ptr::null_mut(),
        };
        let session = FWPM_SESSION0 {
            displayData: display,
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..unsafe { std::mem::zeroed() }
        };
        let mut engine: HANDLE = std::ptr::null_mut();
        // SAFETY: the session outlives the call, and a place for the handle.
        check(unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        })?;
        // From here, dropping it closes the engine and all it holds.
        let this = StrictRoute { engine };

        let sublayer_key = GUID::from_u128(rand::random());
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: sublayer_key,
            displayData: display,
            weight: 0xFFFF,
            ..unsafe { std::mem::zeroed() }
        };
        // SAFETY: as above.
        check(unsafe { FwpmSubLayerAdd0(engine, &sublayer, std::ptr::null_mut()) })?;

        let add = |layer: GUID,
                   weight: u8,
                   conditions: &mut [FWPM_FILTER_CONDITION0],
                   action: FWP_ACTION_TYPE,
                   flags: u32|
         -> io::Result<()> {
            let filter = FWPM_FILTER0 {
                displayData: display,
                flags,
                layerKey: layer,
                subLayerKey: sublayer_key,
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: weight },
                },
                numFilterConditions: conditions.len() as u32,
                filterCondition: if conditions.is_empty() {
                    std::ptr::null_mut()
                } else {
                    conditions.as_mut_ptr()
                },
                action: FWPM_ACTION0 {
                    r#type: action,
                    ..unsafe { std::mem::zeroed() }
                },
                ..unsafe { std::mem::zeroed() }
            };
            let mut id = 0u64;
            // SAFETY: the filter and its conditions outlive the call.
            check(unsafe { FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut id) })
                .map_err(|e| {
                    io::Error::new(e.kind(), format!("filter of weight {}: {}", weight, e))
                })
        };
        let layers = [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ];

        // 13: sail itself, whatever else is blocked.
        let exe = std::env::current_exe()?;
        let exe = wide(&exe.to_string_lossy());
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        // SAFETY: a NUL-terminated path; the blob is freed below.
        check(unsafe { FwpmGetAppIdFromFileName0(exe.as_ptr(), &mut app_id) })?;
        let own = (|| -> io::Result<()> {
            for layer in layers {
                let mut condition = [FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_ALE_APP_ID,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_BLOB_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
                    },
                }];
                add(
                    layer,
                    13,
                    &mut condition,
                    FWP_ACTION_PERMIT,
                    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                )?;
            }
            Ok(())
        })();
        // SAFETY: the blob FwpmGetAppIdFromFileName0 allocated, freed once.
        unsafe { FwpmFreeMemory0(&mut app_id as *mut _ as *mut *mut core::ffi::c_void) };
        own?;

        // 12: no IPv6 at all, when the TUN has none.
        if !ipv6 {
            add(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                12,
                &mut [],
                FWP_ACTION_BLOCK,
                0,
            )?;
        }

        // 11: what goes through the TUN.
        for (layer, has) in layers.into_iter().zip([ipv4, ipv6]) {
            if !has {
                continue;
            }
            let mut condition = [FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_LOCAL_INTERFACE_INDEX,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint32: index },
                },
            }];
            add(layer, 11, &mut condition, FWP_ACTION_PERMIT, 0)?;
        }

        // 10: DNS elsewhere.
        for layer in layers {
            let mut condition = [FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: 53 },
                },
            }];
            add(layer, 10, &mut condition, FWP_ACTION_BLOCK, 0)?;
        }
        Ok(this)
    }
}
