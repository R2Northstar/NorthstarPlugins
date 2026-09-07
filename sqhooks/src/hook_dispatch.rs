use rrplug::{
    bindings::squirreldatatypes::SQObject, high::squirrel_traits::PushToSquirrelVm,
    mid::squirrel::sqvm_to_context, prelude::*,
};
use std::ptr::NonNull;

use crate::{
    hook_install::HOOKS,
    utils::{new_closure, null_sq_object, wrap_in_object},
    variadic::Variadic,
};

#[rrplug::sqfunction(VM = "SERVER | UI | CLIENT", ExportName = "__CallHook")]
pub fn call_hook(function_id: String, args: Variadic<SQObject>) -> SQObject {
    let context = unsafe { sqvm_to_context(sqvm) };
    let mut hooks = HOOKS.lock();
    let hooks = hooks.entry(context).or_default();
    let hook = hooks
        .get_mut(&function_id)
        .expect("non existent function id passed to trampoline");

    if hook.arg_count != args.vargs.len() as u32 {
        unsafe {
            (sq_functions.sq_raiseerror)(
                sqvm.as_ptr(),
                c"wrong arg amount given to trampoline function"
                    .as_ptr()
                    .cast(),
            );
        }
        return null_sq_object();
    }

    log::info!("hooks len {}", hook.hook_queue.len());
    log::info!("recursive started");
    log::info!("hooks.current_hook {}", hook.current_hook);
    hook.current_hook = hook.current_hook.saturating_sub(1);

    call_hook_inner(
        sqvm,
        sq_functions,
        wrap_in_object(new_closure(sqvm, unsafe {
            hook.hook_queue[hook.current_hook + 1].copy().as_ref()
        })),
        hook.current_hook
            .checked_sub(1)
            .map(|_| hook.trampoline.copy()),
        args.vargs,
    )
}

fn call_hook_inner(
    sqvm: NonNull<HSquirrelVM>,
    sq_functions: &SquirrelFunctions,
    mut callable: SQObject,
    next_func: Option<SQObject>,
    args: Vec<SQObject>,
) -> SQObject {
    let args_count = next_func.iter().chain(args.iter()).count();
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
        // TODO: what to with errors?
    }

    unsafe {
        sqvm.as_ref()
            ._stack
            .add(sqvm.as_ref()._top as usize - 1)
            .as_ref()
            .map(|obj| *obj)
            .unwrap_or_else(null_sq_object)
    }
}
