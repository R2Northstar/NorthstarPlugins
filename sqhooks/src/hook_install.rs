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
        as_func_proto, clone_func_name, compile_trampoline, get_from_sq_string, wrap_in_object,
    },
};

pub static HOOKS: LazyLock<Mutex<HashMap<ScriptContext, HashMap<String, Hook>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static ORG_ID_MAP: LazyLock<Mutex<HashMap<usize, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static HOOK_QUEUE: LazyLock<Mutex<HashMap<ScriptContext, Vec<(String, String)>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static EXTRACT: LazyLock<Mutex<HashMap<ScriptContext, Option<UnsafeHandle<*mut SQClosure>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub static FUN: Mutex<Option<UnsafeHandle<*mut SQSharedState>>> = Mutex::new(None);

static_detour! {
    static Server_SQFuncStateBuildProto: unsafe extern "C" fn(*mut SQFuncState) -> *mut SQFunctionProtoB;
    static Server_SQClosureNew: unsafe extern "C" fn(*mut SQClosure, *mut SQSharedState, *mut SQObject) -> *mut SQClosure;
    static Client_SQFuncStateBuildProto: unsafe extern "C" fn(*mut SQFuncState) -> *mut SQFunctionProtoB;
    static Client_SQClosureNew: unsafe extern "C" fn(*mut SQClosure, *mut SQSharedState, *mut SQObject) -> *mut SQClosure;
}

#[derive(Debug)]
pub struct Hook {
    pub hook_queue: Vec<UnsafeHandle<NonNull<SQFunctionProto>>>,
    pub current_hook: usize,
    pub trampoline: Option<UnsafeHandle<SQObject>>,
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
                Client_SQClosureNew
                    .initialize(
                        transmute::<
                            *const std::ffi::c_void,
                            unsafe extern "C" fn(
                                *mut SQClosure,
                                *mut SQSharedState,
                                *mut SQObject,
                            ) -> *mut SQClosure,
                        >(dll.offset(0x1c60)),
                        sqclosure_new_hook_client,
                    )
                    .expect("cannot initialize Client_SQClosureNew")
                    .enable()
                    .expect("cannot hook Client_SQClosureNew");
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

                Server_SQClosureNew
                    .initialize(
                        transmute::<
                            *const std::ffi::c_void,
                            unsafe extern "C" fn(
                                *mut SQClosure,
                                *mut SQSharedState,
                                *mut SQObject,
                            ) -> *mut SQClosure,
                        >(dll.offset(0x1c60)),
                        sqclosure_new_hook_server,
                    )
                    .expect("cannot initialize Server_SQClosureNew")
                    .enable()
                    .expect("cannot hook Server_SQClosureNew");
            }
            _ => {}
        }
    }
}

fn sqclosure_new_hook_client(
    this: *mut SQClosure,
    ss: *mut SQSharedState,
    func: *mut SQObject,
) -> *mut SQClosure {
    sqclosure_new_hook(
        |this, ss, func| unsafe { Client_SQClosureNew.call(this, ss, func) },
        this,
        ss,
        func,
    )
}

fn sqclosure_new_hook_server(
    this: *mut SQClosure,
    ss: *mut SQSharedState,
    func: *mut SQObject,
) -> *mut SQClosure {
    sqclosure_new_hook(
        |this, ss, func| unsafe { Server_SQClosureNew.call(this, ss, func) },
        this,
        ss,
        func,
    )
}

// notes about alternate solutions
// currently I am more pivoting towards manually writing the proto but another
// that could be done is to hook a function that sets up the call info for every
// execution (server.dll+0x02dd20) which means the hook insertions will be working
// in the hot path of the sqvm therefore it needs to be hyper optimized one of the
// ways to achieve that is by pre allocating a trampoline. the trampoline would
// have to be allocated right as the compiler ends compiling since it's not
// possible to run a compiler inside of a compiler and execution can begin right as
// the compiler does it's job => a lot of work finding all the compiler invocations
fn sqclosure_new_hook(
    org: impl Fn(*mut SQClosure, *mut SQSharedState, *mut SQObject) -> *mut SQClosure + 'static,
    this: *mut SQClosure,
    ss: *mut SQSharedState,
    func: *mut SQObject,
) -> *mut SQClosure {
    let org_to_id_map = ORG_ID_MAP.lock();

    if let Some(function_name) = SQHandle::<SQFunctionProto>::try_new(unsafe { func.read() })
        .ok()
        .as_ref()
        .and_then(|func| unsafe { func.get()._funcName.as_ref() })
        .and_then(|name| get_from_sq_string(name))
    {
        let mut hooks = HOOKS.lock();
        let csqvm = unsafe {
            ss.as_ref()
                .expect("shared state should be valid")
                .cSquirrelVM
                .as_ref()
                .expect("csquirrelvm should be valid")
        };

        let context_hooks = hooks
            .entry(ScriptContext::try_from(csqvm.vmContext).expect("somehow got invalid context"))
            .or_default();
        if let Some(key) = context_hooks
            .keys()
            .find(|function_id| function_id.ends_with(function_name))
        {
            log::info!("new closure {function_name} : {key}");
        } else {
            log::info!("new closure {function_name}");
        }
    }

    let func = if let Some((function_id, org_proto_handle)) = unsafe { func.as_ref() }
        .copied()
        .and_then(|obj| SQHandle::<SQFunctionProto>::try_new(obj).ok())
        .and_then(|func| {
            Some((
                org_to_id_map.get(&(std::ptr::from_ref(func.get()) as usize))?,
                func,
            ))
        }) {
        let mut hooks = HOOKS.lock();
        let csqvm = unsafe {
            ss.as_ref()
                .expect("shared state should be valid")
                .cSquirrelVM
                .as_ref()
                .expect("csquirrelvm should be valid")
        };
        let sqvm = NonNull::new(csqvm.sqvm).expect("sqvm should be valid");

        let context_hooks = hooks
            .entry(ScriptContext::try_from(csqvm.vmContext).expect("somehow got invalid context"))
            .or_default();
        log::info!("found {function_id}");

        if let Some(hook) = context_hooks.get_mut(function_id) {
            if let Some(trampoline) = &mut hook.trampoline {
                trampoline.get_mut() as *mut SQObject // hopefully the lifetime is good
            } else {
                log::info!("creating a trampoline for {function_id}");
                let trampoline_name = hook_dispatch::call_hook().sq_func_name;

                let (closure_trampoline, mut trampoline) = match compile_trampoline(
                    sqvm,
                    SQFUNCTIONS.from_sqvm(sqvm),
                    org_proto_handle.get().into(),
                    function_id,
                    &trampoline_name,
                ) {
                    Ok(o) => o,
                    Err(err) => {
                        log::warn!(
                            "error occurred while building trampoline memory may be leaked : {err}"
                        );
                        return org(this, ss, func);
                    }
                };

                clone_func_name(org_proto_handle.get(), unsafe { trampoline.as_mut() });

                hook.trampoline =
                    Some(unsafe { UnsafeHandle::new(wrap_in_object(closure_trampoline)) });

                hook.trampoline
                    .as_mut()
                    .expect("there was just a write to this")
                    .get_mut() as *mut SQObject
            }
        } else {
            func
        }
    } else {
        func
    };

    org(this, ss, func)
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

        let orig = NonNull::new(org(state).cast::<SQFunctionProto>())
            .expect("critical assertion violated");

        HOOKS.lock().entry(context).or_default().insert(
            function_id.clone(),
            Hook {
                hook_queue: vec![unsafe { UnsafeHandle::new(orig) }],
                current_hook: 1, // top most hook
                trampoline: None,
                arg_count: state._parametersSize,
            },
        );

        FUN.lock()
            .replace(unsafe { UnsafeHandle::new(sqvm.as_ref().sharedState) });

        return orig.as_ptr().cast();
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
