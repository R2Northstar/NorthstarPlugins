use rrplug::prelude::*;

use crate::bindings::{CLIENT_FUNCTIONS, ClientFunctions, SERVER_FUNCTIONS, ServerFunctions};

pub struct SQHooks;

mod bindings;
mod hook_dispatch;
mod hook_install;
mod pre_sqvm;
mod utils;
mod variadic;

impl Plugin for SQHooks {
    const PLUGIN_INFO: PluginInfo =
        PluginInfo::new(c"sqhooks", c"SQHOOKPLG", c"SQHOOKS", PluginContext::all());

    fn new(_reloaded: bool) -> Self {
        register_sq_functions(hook_install::hook_on);

        Self {}
    }
    fn on_dll_load(
        &self,
        _engine_data: Option<&EngineData>,
        dll_ptr: &DLLPointer,
        _engine_token: EngineToken,
    ) {
        pre_sqvm::init_hooks(dll_ptr);
        hook_install::init_hooks(dll_ptr);

        unsafe {
            ServerFunctions::try_init(dll_ptr, &SERVER_FUNCTIONS);
            ClientFunctions::try_init(dll_ptr, &CLIENT_FUNCTIONS);
        }
    }

    fn on_sqvm_destroyed(&self, sqvm_handle: &CSquirrelVMHandle, _engine_token: EngineToken) {
        for hook in hook_install::HOOKS
            .lock()
            .entry(sqvm_handle.get_context())
            .or_default()
            .values_mut()
        {
            // decrement ref count
            // SAFETY: ref count is located in the same offset for all refcounted objected
            unsafe {
                hook.trampoline
                    .get()
                    ._VAL
                    .asString
                    .as_mut()
                    .expect("invariant violated in on_sqvm_destroyed")
                    .uiRef -= 1;
            };

            for func in hook.hook_queue.iter_mut() {
                // decrement ref count
                unsafe { func.get_mut().as_mut().uiRef -= 1 };
            }
        }
    }
}

entry!(SQHooks);
