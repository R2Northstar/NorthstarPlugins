#![allow(clippy::too_many_arguments, clippy::type_complexity)]

use parking_lot::Mutex;
use retour::static_detour;
use rrplug::{
    bindings::squirreldatatypes::{SQClosure, SQFunctionProto, SQObject, SQString},
    high::{UnsafeHandle, squirrel::SQHandle, squirrel_traits::IsSQObject},
    mid::squirrel::sqvm_to_context,
    prelude::*,
};
use std::{collections::HashMap, mem::transmute, ptr::NonNull, sync::LazyLock};

use crate::{
    bindings::{SQFuncState, SQFunctionProtoB},
    hook_dispatch,
    utils::{
        as_func_proto, compile_trampoline, get_from_sq_string, print_sqobject, wrap_in_object,
    },
};

pub static HOOKS: LazyLock<Mutex<HashMap<ScriptContext, HashMap<String, Hook>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static HOOK_QUEUE: LazyLock<Mutex<HashMap<ScriptContext, Vec<(String, String)>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static EXTRACT: LazyLock<Mutex<HashMap<ScriptContext, Option<UnsafeHandle<*mut SQClosure>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static TYPE_DESCRIPTOR_ADDRS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

static_detour! {
    static Server_SQFuncStateBuildProto: unsafe extern "C" fn(*mut SQFuncState) -> *mut SQFunctionProtoB;
    static Client_SQFuncStateBuildProto: unsafe extern "C" fn(*mut SQFuncState) -> *mut SQFunctionProtoB;
}

#[derive(Debug)]
pub struct Hook {
    pub hook_queue: Vec<UnsafeHandle<NonNull<SQFunctionProto>>>,
    pub current_hook: usize,
    pub trampoline: UnsafeHandle<SQObject>,
    pub arg_count: u32,
}

pub fn prepare_hook(context: ScriptContext, source_path: String, function_name: String) {
    HOOK_QUEUE
        .lock()
        .entry(context)
        .or_default()
        .push((source_path, function_name));
}

pub fn init_hooks(dll: &DLLPointer) {
    unsafe {
        match dll.which_dll() {
            WhichDll::Client => {
                Client_SQFuncStateBuildProto
                    .initialize(
                        transmute::<
                            *const std::ffi::c_void,
                            unsafe extern "C" fn(*mut SQFuncState) -> *mut SQFunctionProtoB,
                        >(dll.offset(0x67340)),
                        sqfunc_state_build_proto_hook_client,
                    )
                    .expect("cannot initialize Client_SQFuncStateBuildProto")
                    .enable()
                    .expect("cannot hook Client_SQFuncStateBuildProto");
            }

            WhichDll::Server => {
                Server_SQFuncStateBuildProto
                    .initialize(
                        transmute::<
                            *const std::ffi::c_void,
                            unsafe extern "C" fn(*mut SQFuncState) -> *mut SQFunctionProtoB,
                        >(dll.offset(0x672d0)),
                        sqfunc_state_build_proto_hook_server,
                    )
                    .expect("cannot initialize Server_SQFuncStateBuildProto")
                    .enable()
                    .expect("cannot hook Server_SQFuncStateBuildProto");
            }
            _ => {}
        }
    }
}

fn sqfunc_state_build_proto_hook_client(state: *mut SQFuncState) -> *mut SQFunctionProtoB {
    sqfunc_state_build_proto_hook(
        |state| unsafe { Client_SQFuncStateBuildProto.call(state) },
        state,
    )
}

fn sqfunc_state_build_proto_hook_server(state: *mut SQFuncState) -> *mut SQFunctionProtoB {
    sqfunc_state_build_proto_hook(
        |state| unsafe { Server_SQFuncStateBuildProto.call(state) },
        state,
    )
}

fn sqfunc_state_build_proto_hook(
    org: fn(*mut SQFuncState) -> *mut SQFunctionProtoB,
    state: *mut SQFuncState,
) -> *mut SQFunctionProtoB {
    let state = unsafe {
        state
            .as_mut()
            .expect("null func state in builder not found")
    };
    let Some(sqvm) = (unsafe {
        state
            .sharedState
            .as_mut()
            .and_then(|ss| ss.cSquirrelVM.as_mut())
            .and_then(|csqvm| csqvm.sqvm.as_mut().map(NonNull::from_mut))
    }) else {
        log::warn!("couldn't find sqvm in build proto hook");
        return org(state);
    };
    let context = unsafe { sqvm_to_context(sqvm) };

    let handle = SQHandle::try_new(state.funcName).ok();
    let Some(function_name) = handle
        .as_ref()
        .and_then(|handle| get_from_sq_string(handle.get()))
    else {
        return org(state);
    };

    let handle = SQHandle::try_new(state.fileName).ok();
    let Some(source_path) = handle
        .as_ref()
        .and_then(|handle| get_from_sq_string(handle.get()))
    else {
        return org(state);
    };

    if HOOK_QUEUE
        .lock()
        .entry(context)
        .or_default()
        .iter()
        .any(|(source, name)| source.ends_with(source_path) && name == function_name)
    {
        assert_eq!(
            state._defaultParamSize, 0,
            "man idk what to with default parameters, yell at catornot or smth"
        );
        log::info!("installing hook for {function_name}");

        let function_id = source_path.to_string() + function_name;

        let trampoline_name = hook_dispatch::call_hook().sq_func_name;

        let orig = unsafe {
            let mut orig = UnsafeHandle::new(
                NonNull::new(org(state).cast::<SQFunctionProto>())
                    .expect("critical assertion violated"),
            );
            // increment ref count
            orig.get_mut().as_mut().uiRef += 1;
            orig
        };

        let (closure_trampoline, trampoline) = match compile_trampoline(
            sqvm,
            // SQFUNCTIONS.from_sqvm(sqvm),
            unsafe { orig.copy().cast().as_ref() },
            &function_id,
            &trampoline_name,
        ) {
            Ok(o) => o,
            Err(err) => {
                log::warn!("error occurred while building trampoline memory may be leaked : {err}");
                return orig.take().as_ptr().cast();
            }
        };

        let trampoline_proto = unsafe { trampoline.cast::<SQFunctionProtoB>().as_ref() };
        (0..dbg!(trampoline_proto.skippedInstruction.arg2 as usize))
            .filter_map(|i| unsafe { trampoline_proto.instruction.as_ptr().add(i).as_ref() })
            .for_each(|ins| log::info!("{ins:?}"));
        (0..dbg!(trampoline_proto.localVarInfoSize as usize))
            .filter_map(|i| unsafe { trampoline_proto.localVarInfos.add(i).as_ref() })
            .for_each(|info| {
                log::info!(
                    "info: {info:?}, {:?}, {:?}",
                    SQHandle::try_new(info.name)
                        .ok()
                        .and_then(|name| get_from_sq_string(name.get()).map(ToString::to_string)),
                    unsafe { info.type_descriptor.as_ref() },
                );
            });
        (0..dbg!(trampoline_proto.nParameters as usize))
            .filter_map(|i| unsafe { trampoline_proto._parameters.add(i).as_ref() })
            .for_each(print_sqobject);
        log::info!("functions");
        (0..dbg!(trampoline_proto.nfunctions as usize))
            .filter_map(|i| unsafe { trampoline_proto._functions.add(i).as_ref() })
            .for_each(print_sqobject);
        (0..dbg!(trampoline_proto.otherVarInfoSize as usize))
            .filter_map(|i| unsafe { trampoline_proto._otherVarInfo.add(i).as_ref() })
            .for_each(|info| log::info!("other_info: {info:?}"));
        (0..dbg!(trampoline_proto.nDefaultParams as usize))
            .filter_map(|i| unsafe { trampoline_proto.objectArray_F0.add(i).as_ref() })
            .for_each(print_sqobject);
        log::info!("literals");
        (0..dbg!(trampoline_proto.literalsSize as usize))
            .filter_map(|i| unsafe { trampoline_proto.literals.add(i).as_ref() })
            .for_each(print_sqobject);
        log::info!("original locals");
        (0..dbg!(unsafe {
            orig.get()
                .cast::<SQFunctionProtoB>()
                .as_ref()
                .localVarInfoSize as usize
        }))
            .filter_map(|i| unsafe {
                orig.get()
                    .cast::<SQFunctionProtoB>()
                    .as_ref()
                    .localVarInfos
                    .add(i)
                    .as_ref()
            })
            .for_each(|info| {
                log::info!(
                    "info: {info:?}, {:?}",
                    SQHandle::try_new(info.name)
                        .ok()
                        .and_then(|name| get_from_sq_string(name.get()).map(ToString::to_string))
                )
            });

        HOOKS.lock().entry(context).or_default().insert(
            function_id.clone(),
            Hook {
                hook_queue: vec![orig],
                current_hook: 1, // top most hook
                trampoline: unsafe { UnsafeHandle::new(wrap_in_object(closure_trampoline)) },
                arg_count: state._parametersSize.saturating_sub(1), // _parametersSize also includes root table so we skip that
            },
        );

        return trampoline.as_ptr().cast();
    }

    let func = unsafe { org(state).as_mut().unwrap() };

    // log::info!(
    //     "{} locals",
    //     SQHandle::try_new(func.funcName)
    //         .ok()
    //         .and_then(|name| get_from_sq_string(name.get()).map(ToString::to_string))
    //         .unwrap_or_default()
    // );
    // (0..dbg!(func.localVarInfoSize as usize))
    //     .filter_map(|i| unsafe { func.localVarInfos.add(i).as_ref() })
    //     .for_each(|info| {
    //         TYPE_DESCRIPTOR_ADDRS
    //             .lock()
    //             .push(info.type_descriptor as usize);
    //         log::info!(
    //             "info: {info:?}, {:?}, {:?}",
    //             SQHandle::try_new(info.name)
    //                 .ok()
    //                 .and_then(|name| get_from_sq_string(name.get()).map(ToString::to_string)),
    //             unsafe { info.type_descriptor.as_ref() },
    //         )
    //     });

    func
}

#[rrplug::sqfunction(VM = "SERVER | UI | CLIENT", ExportName = "HookOn")]
pub fn hook_on(
    function_id: SQHandle<SQString>,
    hook_func: SQHandle<SQClosure>,
) -> Result<(), String> {
    let context = unsafe { sqvm_to_context(sqvm) };
    let mut hooks = HOOKS.lock();
    let hooks = hooks.entry(context).or_default();
    let Some(hook) =
        get_from_sq_string(function_id.get()).and_then(|function_id| hooks.get_mut(function_id))
    else {
        return Err(
            "couldn't find the function from it's function id of ".to_string()
                + get_from_sq_string(function_id.get()).unwrap_or_default(),
        );
    };

    let mut proto_func = match as_func_proto(hook_func.take_obj()) {
        Ok(proto_func) => proto_func,
        Err(err) => return Err(err.to_string()),
    };

    // increment ref count
    unsafe {
        proto_func.as_mut().uiRef += 1;
    }

    hook.hook_queue
        .push(unsafe { UnsafeHandle::new(proto_func) });
    hook.current_hook = hook.hook_queue.len();

    Ok(())
}

#[rrplug::sqfunction(VM = "SERVER | UI | CLIENT", ExportName = "__EXTRACT")]
pub fn extract(hook_func: SQObject) {
    assert!(
        hook_func._Type == SQClosure::OT_TYPE,
        "passed wrong value to __EXTRACT"
    );

    let context = unsafe { sqvm_to_context(sqvm) };
    let mut lock = EXTRACT.lock();
    lock.entry(context)
        .or_default()
        .replace(unsafe { UnsafeHandle::new(hook_func._VAL.asClosure) });
}
