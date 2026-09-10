use rrplug::{
    bindings::squirreldatatypes::{SQObject, SQString},
    high::{squirrel::SQHandle, squirrel_traits::PushToSquirrelVm},
    mid::squirrel::sqvm_to_context,
    prelude::*,
};
use std::ptr::NonNull;

use crate::{
    hook_install::HOOKS,
    utils::{
        as_func_proto, free_sqobject, get_from_sq_string, increment_ref_sqobject, new_closure,
        null_sq_object, print_sqobject, wrap_in_object,
    },
    variadic::Variadic,
};

#[rrplug::sqfunction(VM = "SERVER | UI | CLIENT", ExportName = "__CallHook")]
pub fn call_hook(
    function_id: SQHandle<SQString>,
    args: Variadic<SQObject>,
) -> Result<SQObject, String> {
    let context = unsafe { sqvm_to_context(sqvm) };
    let mut lock = HOOKS.lock();
    let hooks = lock.entry(context).or_default();

    let Some(hook) =
        get_from_sq_string(function_id.get()).and_then(|function_id| hooks.get_mut(function_id))
    else {
        Err(
            "couldn't find the function from it's function id of ".to_string()
                + get_from_sq_string(function_id.get()).unwrap_or_default(),
        )?
    };

    if hook.arg_count > args.vargs.len() as u32 {
        Err(&"wrong arg amount given to trampoline function".to_string())?
    }
    let real_arg_count = hook.arg_count as usize;

    log::info!(
        "hooks.hooks len {} content {:?}",
        hook.hook_queue.len(),
        hook.hook_queue
            .iter()
            .filter_map(|proto| Some(
                get_from_sq_string(unsafe { proto.get().as_ref()._funcName.as_ref()? })
                    .unwrap_or("unknown")
            ))
            .collect::<Vec<_>>()
    );
    log::info!("hooks.current_hook {}", hook.current_hook);

    hook.current_hook = hook.current_hook.saturating_sub(1);

    let next_closure = increment_ref_sqobject(wrap_in_object(new_closure(sqvm, unsafe {
        hook.hook_queue[hook.current_hook].copy().as_ref()
    })));

    let next_func = hook
        .current_hook
        .checked_sub(1)
        .map(|_| hook.trampoline.copy());

    drop(lock);

    let out = call_hook_inner(
        sqvm,
        sq_functions,
        next_closure,
        next_func,
        &args.vargs[0..real_arg_count],
    );

    free_sqobject(next_closure);

    let mut lock = HOOKS.lock();
    let hooks = lock.entry(context).or_default();

    let hook = get_from_sq_string(function_id.get())
        .and_then(|function_id| hooks.get_mut(function_id))
        .expect("we are in hook rn");

    hook.current_hook = hook.hook_queue.len();

    drop(lock);

    out
}

fn call_hook_inner(
    sqvm: NonNull<HSquirrelVM>,
    sq_functions: &SquirrelFunctions,
    mut callable: SQObject,
    next_func: Option<SQObject>,
    args: &[SQObject],
) -> Result<SQObject, String> {
    log::info!(
        "calling {}",
        as_func_proto(callable)
            .ok()
            .and_then(|proto| get_from_sq_string(unsafe { proto.as_ref()._funcName.as_ref()? }))
            .unwrap_or("unknown")
    );

    let args_count = next_func.iter().chain(args.iter()).count() + 1; // +1 for this pointer

    unsafe {
        (sq_functions.sq_pushobject)(sqvm.as_ptr(), &mut callable);
        (sq_functions.sq_pushroottable)(sqvm.as_ptr());
    }

    if let Some(func) = next_func {
        func.push_to_sqvm(sqvm, sq_functions);
    }

    for arg in args {
        arg.push_to_sqvm(sqvm, sq_functions);
    }

    if unsafe {
        (sq_functions.sq_call)(sqvm.as_ptr(), args_count as i32, true as u32, true as u32)
            == rrplug::bindings::squirrelclasstypes::SQRESULT::SQRESULT_ERROR
    } {
        Err(format!(
            "couldn't call {}: {}",
            as_func_proto(callable)
                .ok()
                .and_then(|proto| get_from_sq_string(unsafe { proto.as_ref()._funcName.as_ref()? }))
                .unwrap_or("unknown"),
            SQHandle::try_new(unsafe { sqvm.as_ref()._lasterror })
                .ok()
                .and_then(|error| Some(get_from_sq_string(error.get())?.to_string()))
                .unwrap_or_default()
        ))?
    }

    unsafe {
        Ok(sqvm
            .as_ref()
            ._stack
            .add(sqvm.as_ref()._top as usize - 1)
            .as_ref()
            .map(|obj| *obj)
            .unwrap_or_else(null_sq_object))
    }
}
