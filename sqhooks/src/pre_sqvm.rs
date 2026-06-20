use retour::static_detour;
use rrplug::{
    bindings::squirreldatatypes::CSquirrelVM,
    mid::squirrel::{manually_register_sq_functions, sqvm_to_context},
    prelude::*,
};
use std::{ffi::c_void, mem::transmute};

use crate::{hook_dispatch, hook_install::prepare_hook};

static_detour! {
    static Server_CSquirrelVM_InitGcMaybe: unsafe extern "C" fn(*mut CSquirrelVM, *mut HSquirrelVM, u32, usize);
    static Client_CSquirrelVM_InitGcMaybe: unsafe extern "C" fn(*mut CSquirrelVM, *mut HSquirrelVM, u32, usize);
}

pub fn init_hooks(dll: &DLLPointer) {
    unsafe {
        match dll.which_dll() {
            WhichDll::Client => {
                Client_CSquirrelVM_InitGcMaybe
                    .initialize(
                        transmute::<
                            *const c_void,
                            unsafe extern "C" fn(*mut CSquirrelVM, *mut HSquirrelVM, u32, usize),
                        >(dll.offset(0x44df0)),
                        hook_csquirrel_vm_init_gc_client,
                    )
                    .expect("cannot initialize Client_CSquirrelVM_InitGcMaybe")
                    .enable()
                    .expect("cannot hook Client_CSquirrelVM_InitGcMaybe");
            }

            WhichDll::Server => {
                Server_CSquirrelVM_InitGcMaybe
                    .initialize(
                        transmute::<
                            *const c_void,
                            unsafe extern "C" fn(
                                *mut rrplug::bindings::squirreldatatypes::CSquirrelVM,
                                *mut rrplug::prelude::HSquirrelVM,
                                u32,
                                usize,
                            ),
                        >(dll.offset(0x44d90)),
                        hook_csquirrel_vm_init_gc_server,
                    )
                    .expect("cannot initialize Server_CSquirrelVM_InitGcMaybe")
                    .enable()
                    .expect("cannot hook Server_CSquirrelVM_InitGcMaybe");
            }
            _ => {}
        }
    }
}

fn hook_csquirrel_vm_init_gc_client(
    csqvm: *mut CSquirrelVM,
    sqvm: *mut HSquirrelVM,
    unk1: u32,
    unk2: usize,
) {
    unsafe { Client_CSquirrelVM_InitGcMaybe.call(csqvm, sqvm, unk1, unk2) };
    hook_csquirrel_vm_init_gc(csqvm, sqvm, unk1, unk2)
}
fn hook_csquirrel_vm_init_gc_server(
    csqvm: *mut CSquirrelVM,
    sqvm: *mut HSquirrelVM,
    unk1: u32,
    unk2: usize,
) {
    unsafe { Server_CSquirrelVM_InitGcMaybe.call(csqvm, sqvm, unk1, unk2) };
    hook_csquirrel_vm_init_gc(csqvm, sqvm, unk1, unk2)
}
fn hook_csquirrel_vm_init_gc(
    csqvm: *mut CSquirrelVM,
    _sqvm: *mut HSquirrelVM,
    _unk1: u32,
    _unk2: usize,
) {
    _ = mid::squirrel::SQFUNCTIONS.try_init(); // make sure all functions exist
    _ = unsafe { manually_register_sq_functions(&mut *csqvm, &register_hook()) };
    _ = unsafe { manually_register_sq_functions(&mut *csqvm, &hook_dispatch::call_hook()) };
}

#[rrplug::sqfunction(VM = "SERVER | UI | CLIENT", ExportName = "SQRegisterHook")]
fn register_hook(source_path: String, function_name: String) {
    prepare_hook(unsafe { sqvm_to_context(sqvm) }, source_path, function_name);
}
