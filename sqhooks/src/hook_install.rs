#![allow(clippy::too_many_arguments, clippy::type_complexity)]

use parking_lot::Mutex;
use retour::static_detour;
use rrplug::{
    bindings::squirreldatatypes::{
        SQClosure, SQFunctionProto, SQObject, SQObjectValue, SQSharedState,
    },
    high::{
        UnsafeHandle,
        squirrel::{SQHandle, compile_string},
        squirrel_traits::IsSQObject,
    },
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
    utils::{as_func_proto, get_from_sq_string},
};

pub static HOOKS: LazyLock<Mutex<HashMap<ScriptContext, HashMap<String, Hook>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static HOOK_QUEUE: LazyLock<Mutex<HashMap<ScriptContext, Vec<(String, String)>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

static_detour! {
    static Server_SQFunctionProtoCreate: unsafe extern "C" fn(*mut SQSharedState, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32) -> *mut SQFunctionProtoB;
    static Client_SQFunctionProtoCreate: unsafe extern "C" fn(*mut SQSharedState, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32) -> *mut SQFunctionProtoB;
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
                Client_SQFunctionProtoCreate
                    .initialize(
                        transmute::<
                            *const std::ffi::c_void,
                            unsafe extern "C" fn(
                                *mut SQSharedState,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                            )
                                -> *mut SQFunctionProtoB,
                        >(dll.offset(0x64920)),
                        hook_sq_function_proto_client,
                    )
                    .expect("cannot initialize Client_SQFunctionProtoCreate")
                    .enable()
                    .expect("cannot hook Client_SQFunctionProtoCreate");

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
                Server_SQFunctionProtoCreate
                    .initialize(
                        transmute::<
                            *const std::ffi::c_void,
                            unsafe extern "C" fn(
                                *mut SQSharedState,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                                i32,
                            )
                                -> *mut SQFunctionProtoB,
                        >(dll.offset(0x648c0)),
                        hook_sq_function_proto_server,
                    )
                    .expect("cannot initialize Server_SQFunctionProtoCreate")
                    .enable()
                    .expect("cannot hook Server_SQFunctionProtoCreate");

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
    let sqvm = unsafe {
        state
            .sharedState
            .as_mut()
            .and_then(|ss| ss.cSquirrelVM.as_mut())
            .and_then(|csqvm| csqvm.sqvm.as_mut().map(NonNull::from_mut))
            .expect("null func sqvm in builder not found")
    };
    let context = unsafe { sqvm_to_context(sqvm) };

    let handle = SQHandle::try_new(state.funcName).expect("the function name wasn't a string");
    let Some(function_name) = get_from_sq_string(handle.get()) else {
        return org(state);
    };

    let handle = SQHandle::try_new(state.fileName).expect("the function name wasn't a string");
    let Some(source_path) = get_from_sq_string(handle.get()) else {
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

        let function_id = source_path.to_string() + function_name;

        let orig = unsafe {
            let mut orig = UnsafeHandle::new(
                NonNull::new(org(state).cast::<SQFunctionProto>())
                    .expect("critical assertion violated"),
            );
            // increment ref count
            orig.get_mut().as_mut().uiRef += 1;
            orig
        };

        let args = (1..state._parametersSize)
            .map(|i| "var a".to_string() + &i.to_string() + ",")
            .collect::<String>();
        let args = args.strip_suffix(",").unwrap_or(&args);

        let args_untyped = (1..state._parametersSize)
            .map(|i| "a".to_string() + &i.to_string() + ",")
            .collect::<String>();
        let args_untyped = args_untyped.strip_suffix(",").unwrap_or(&args_untyped);

        // TODO: create this function in hook_dispatch
        let trampoline_name = "HookTrampoline";

        if let Err(err) = compile_string(
            sqvm,
            SQFUNCTIONS.from_sqvm(sqvm),
            true,
            dbg!(format!(
                "return (var function ({args}) {{return {trampoline_name}(\"{function_id}\", {args_untyped})}})"
            )),
        ) {
            err.log();
        };

        let (trampoline, closure_trampoline) = unsafe {
            let sqclosure = sqvm
                .as_ref()
                ._stack
                .add(sqvm.as_ref()._top as usize - 1)
                .as_ref()
                .unwrap()
                ._VAL
                .asClosure
                .as_mut()
                .unwrap();

            (
                sqclosure._function._VAL.asFuncProto.as_ref().unwrap(),
                sqclosure,
            )
        };

        // increment ref count
        closure_trampoline.uiRef += 1;

        HOOKS.lock().entry(context).or_default().insert(
            function_id.clone(),
            Hook {
                hook_queue: vec![orig],
                current_hook: 1, // top most hook
                trampoline: unsafe {
                    UnsafeHandle::new(SQObject {
                        _Type: SQClosure::OT_TYPE,
                        structNumber: 0,
                        _VAL: SQObjectValue {
                            asClosure: ptr::from_ref(closure_trampoline).cast_mut(),
                        },
                    })
                },
                arg_count: state._parametersSize,
            },
        );

        return ptr::from_ref(trampoline).cast_mut().cast();
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

fn hook_sq_function_proto_client(
    ss: *mut SQSharedState,
    ninstructions: i32,
    param_3: i32,
    param_4: i32,
    param_5: i32,
    param_6: i32,
    param_7: i32,
    param_8: i32,
    param_9: i32,
    param_10: i32,
    param_11: i32,
) -> *mut SQFunctionProtoB {
    hook_sq_function_proto(
        |ss: *mut SQSharedState,
         ninstructions: i32,
         param_3: i32,
         param_4: i32,
         param_5: i32,
         param_6: i32,
         param_7: i32,
         param_8: i32,
         param_9: i32,
         param_10: i32,
         param_11: i32| unsafe {
            Client_SQFunctionProtoCreate.call(
                ss,
                ninstructions,
                param_3,
                param_4,
                param_5,
                param_6,
                param_7,
                param_8,
                param_9,
                param_10,
                param_11,
            )
        },
        ss,
        ninstructions,
        param_3,
        param_4,
        param_5,
        param_6,
        param_7,
        param_8,
        param_9,
        param_10,
        param_11,
    )
}

fn hook_sq_function_proto_server(
    ss: *mut SQSharedState,
    ninstructions: i32,
    param_3: i32,
    param_4: i32,
    param_5: i32,
    param_6: i32,
    param_7: i32,
    param_8: i32,
    param_9: i32,
    param_10: i32,
    param_11: i32,
) -> *mut SQFunctionProtoB {
    hook_sq_function_proto(
        |ss: *mut SQSharedState,
         ninstructions: i32,
         param_3: i32,
         param_4: i32,
         param_5: i32,
         param_6: i32,
         param_7: i32,
         param_8: i32,
         param_9: i32,
         param_10: i32,
         param_11: i32| unsafe {
            Server_SQFunctionProtoCreate.call(
                ss,
                ninstructions,
                param_3,
                param_4,
                param_5,
                param_6,
                param_7,
                param_8,
                param_9,
                param_10,
                param_11,
            )
        },
        ss,
        ninstructions,
        param_3,
        param_4,
        param_5,
        param_6,
        param_7,
        param_8,
        param_9,
        param_10,
        param_11,
    )
}

fn hook_sq_function_proto(
    org: fn(
        *mut SQSharedState,
        i32,
        i32,
        i32,
        i32,
        i32,
        i32,
        i32,
        i32,
        i32,
        i32,
    ) -> *mut SQFunctionProtoB,
    ss: *mut SQSharedState,
    ninstructions: i32,
    param_3: i32,
    param_4: i32,
    param_5: i32,
    param_6: i32,
    param_7: i32,
    param_8: i32,
    param_9: i32,
    param_10: i32,
    param_11: i32,
) -> *mut SQFunctionProtoB {
    org(
        ss,
        ninstructions,
        param_3,
        param_4,
        param_5,
        param_6,
        param_7,
        param_8,
        param_9,
        param_10,
        param_11,
    )
}
