#![feature(iter_array_chunks)]

use rrplug::prelude::*;

use crate::bindings::{CLIENT_FUNCTIONS, ClientFunctions, SERVER_FUNCTIONS, ServerFunctions};

mod bindings;
mod hook_dispatch;
mod hook_install;
mod pre_sqvm;
mod utils;
mod variadic;

pub struct SQHooks;

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

    fn on_sqvm_created(&self, _sqvm_handle: &CSquirrelVMHandle, _engine_token: EngineToken) {
        let descriptors = hook_install::TYPE_DESCRIPTOR_ADDRS.lock();

        let min = descriptors
            .iter()
            .copied()
            .map(|addr| addr as isize)
            .enumerate()
            .flat_map(|(i, addr)| {
                descriptors
                    .iter()
                    .copied()
                    .map(|addr| addr as isize)
                    .enumerate()
                    .filter(move |(j, _)| i != *j)
                    .map(move |(_, other_addr)| (other_addr - addr).unsigned_abs())
            })
            .filter(|size| *size != 0)
            .min()
            .unwrap_or(usize::MAX);

        log::info!("the type descriptor size is probably : {min}")
    }

    fn on_sqvm_destroyed(&self, sqvm_handle: &CSquirrelVMHandle, _engine_token: EngineToken) {
        for hook in hook_install::HOOKS
            .lock()
            .remove(&sqvm_handle.get_context())
            .into_iter()
            .flat_map(|hooks| hooks.into_values())
        {
            // free_sqobject(hook.trampoline.take());
            // skip the original proto func
            // for func in hook.hook_queue.into_iter().skip(1) {
            //     free_sqobject(wrap_in_object(func.take()));
            // }
        }
    }
}

entry!(SQHooks);
