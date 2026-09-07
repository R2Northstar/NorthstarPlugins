#![allow(clippy::too_many_arguments, clippy::type_complexity)]

use parking_lot::Mutex;
use retour::static_detour;
use rrplug::{
    bindings::squirreldatatypes::{SQClosure, SQFunctionProto, SQObject, SQSharedState, SQTable},
    high::{UnsafeHandle, squirrel::SQHandle, squirrel_traits::IsSQObject},
    mid::squirrel::sqvm_to_context,
    prelude::*,
};
use std::{
    collections::HashMap,
    mem::transmute,
    ptr::{self, NonNull},
    sync::LazyLock,
};

use crate::{
    bindings::{SQFuncState, SQFunctionProtoB},
    hook_dispatch,
    utils::{
        as_func_proto, clone_func_name, compile_trampoline, get_from_sq_string, print_sqobject,
        wrap_in_object,
    },
};

pub static HOOKS: LazyLock<Mutex<HashMap<ScriptContext, HashMap<String, Hook>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static HOOK_QUEUE: LazyLock<Mutex<HashMap<ScriptContext, Vec<(String, String)>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static EXTRACT: LazyLock<Mutex<HashMap<ScriptContext, Option<UnsafeHandle<*mut SQClosure>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static FUN: Mutex<Option<UnsafeHandle<*mut SQSharedState>>> = Mutex::new(None);

static_detour! {
    static Server_SQFuncStateBuildProto: unsafe extern "C" fn(*mut SQFuncState) -> *mut SQFunctionProtoB;
    static Client_SQFuncStateBuildProto: unsafe extern "C" fn(*mut SQFuncState) -> *mut SQFunctionProtoB;
    static Inspect: unsafe extern "C" fn(*mut SQTable, *mut SQObject, usize) -> usize;
    static Inspect2: unsafe extern "C" fn(usize, usize, usize, usize, u8) -> usize;
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

                // Inspect
                //     .initialize(transmute(dll.offset(0x6aac0)), a)
                //     .expect("cannot initialize Inspect")
                //     .enable()
                //     .expect("cannot hook Inspect");

                // Inspect2
                //     .initialize(transmute(dll.offset(0x34810)), b)
                //     .expect("cannot initialize Inspect2")
                //     .enable()
                //     .expect("cannot hook Inspect2");
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
    log::info!("1 {:?} {:?}", ptr::from_mut(state), state.sharedState);
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

        unsafe {
            log::info!(
                "pre {:?}",
                sqvm.as_ref()
                    .sharedState
                    .as_ref()
                    .unwrap()
                    ._functions
                    .as_ref()
            )
        };
        unsafe {
            log::info!(
                "pre {:?}",
                sqvm.as_ref().sharedState.as_ref().unwrap()._functionsType,
            )
        };

        let orig = unsafe {
            let mut orig = UnsafeHandle::new(
                NonNull::new(org(state).cast::<SQFunctionProto>())
                    .expect("critical assertion violated"),
            );
            // increment ref count
            orig.get_mut().as_mut().uiRef += 1;
            orig
        };

        let (closure_trampoline, mut trampoline) = match compile_trampoline(
            sqvm,
            SQFUNCTIONS.from_sqvm(sqvm),
            state,
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
                    "info: {info:?}, {:?}",
                    SQHandle::try_new(info.name)
                        .ok()
                        .and_then(|name| get_from_sq_string(name.get()).map(ToString::to_string))
                )
            });
        (0..dbg!(trampoline_proto.nParameters as usize))
            .filter_map(|i| unsafe { trampoline_proto._parameters.add(i).as_ref() })
            .for_each(print_sqobject);
        (0..dbg!(trampoline_proto.nNativeClosureMaybe as usize))
            .filter_map(|i| unsafe { trampoline_proto._nativeClosuresMaybe.add(i).as_ref() })
            .for_each(print_sqobject);
        (0..dbg!(trampoline_proto.otherVarInfoSize as usize))
            .filter_map(|i| unsafe { trampoline_proto._otherVarInfo.add(i).as_ref() })
            .for_each(|info| log::info!("other_info: {info:?}"));
        (0..dbg!(trampoline_proto.nDefaultParams as usize))
            .filter_map(|i| unsafe { trampoline_proto.objectArray_F0.add(i).as_ref() })
            .for_each(print_sqobject);

        unsafe { clone_func_name(orig.copy().as_ref(), trampoline.as_mut()) };

        HOOKS.lock().entry(context).or_default().insert(
            function_id.clone(),
            Hook {
                hook_queue: vec![orig],
                current_hook: 1, // top most hook
                trampoline: unsafe { UnsafeHandle::new(wrap_in_object(closure_trampoline)) },
                arg_count: state._parametersSize,
            },
        );

        unsafe {
            log::info!(
                "post {:?}",
                sqvm.as_ref()
                    .sharedState
                    .as_ref()
                    .unwrap()
                    ._functions
                    .as_ref()
            )
        };
        unsafe {
            log::info!(
                "post {:?}",
                sqvm.as_ref().sharedState.as_ref().unwrap()._functionsType
            )
        };

        FUN.lock()
            .replace(unsafe { UnsafeHandle::new(sqvm.as_ref().sharedState) });

        return trampoline.as_ptr().cast();
    }

    org(state)
}

#[rrplug::sqfunction(VM = "SERVER | UI | CLIENT", ExportName = "HookOn")]
pub fn hook_on(function_id: String, hook_func: SQHandle<SQClosure>) -> Option<String> {
    let context = unsafe { sqvm_to_context(sqvm) };
    let mut hooks = HOOKS.lock();
    let hooks = hooks.entry(context).or_default();
    let Some(hook) = hooks.get_mut(&function_id) else {
        return Some(
            "couldn't find the function from it's function id of ".to_string() + &function_id,
        );
    };

    let mut proto_func = match as_func_proto(hook_func.take_obj()) {
        Ok(proto_func) => proto_func,
        Err(err) => return Some(err.to_string()),
    };

    // increment ref count
    unsafe {
        proto_func.as_mut().uiRef += 1;
    }

    hook.current_hook += 1;
    hook.hook_queue
        .push(unsafe { UnsafeHandle::new(proto_func) });

    None
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

// TODO: check return address
fn a(a1: *mut SQTable, a2: *mut SQObject, a3: usize) -> usize {
    unsafe {
        if let Some(shared) = FUN.lock().as_ref() {
            log::info!("a {:?}", shared.get().as_ref().unwrap()._functions);
            log::info!("a {:?}", shared.get().as_ref().unwrap()._functionsType);
            log::info!("a {:?}", a1);
        }

        Inspect.call(a1, a2, a3)
    }
}

fn b(a1: usize, a2: usize, a3: usize, a4: usize, a5: u8) -> usize {
    unsafe {
        log::info!("lock in pls");

        Inspect2.call(a1, a2, a3, a4, a5)
    }
}
