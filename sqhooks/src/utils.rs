use core::str;
use high::squirrel_traits::IsSQObject;
use rrplug::{
    bindings::squirreldatatypes::{
        SQClosure, SQFunctionProto, SQNativeClosure, SQObject, SQObjectType, SQObjectValue,
        SQString, SQTable,
    },
    high::squirrel::SQHandle,
    mid::squirrel::sqvm_to_context,
    prelude::*,
};
use std::ptr::{self, NonNull};

use crate::bindings::{CLIENT_FUNCTIONS, SERVER_FUNCTIONS, SQFunctionProtoB};

pub fn get_native_function<'a>(
    sqvm: NonNull<HSquirrelVM>,
    name: &str,
) -> Option<NonNull<SQNativeClosure>> {
    let table = unsafe {
        sqvm.as_ref()
            .sharedState
            .as_ref()?
            ._tableNativeFunctions
            .as_ref()
    };
    ty_filter(table)
        .filter_map(|(key, closure)| {
            Some((SQHandle::<SQString>::try_new(key.clone()).ok()?, closure))
        })
        .find_map(|(key, closure)| {
            get_from_sq_string(key.get())
                .filter(|cmp_name| *cmp_name == name)
                .map(|_| closure)
        })
        .map(|ptr| NonNull::from_ref(ptr))
}

pub fn ty_filter<'a, T: IsSQObject<'a> + 'a>(
    table: Option<&'a SQTable>,
) -> impl Iterator<Item = (&'a mut SQObject, &'a mut T)> {
    table
        .map(|table| {
            (0..table._numOfNodes as usize)
                .filter_map(move |i| unsafe { table._nodes.add(i).as_mut() })
        })
        .into_iter()
        .flatten()
        .filter_map(move |node| {
            Some((
                &mut node.key,
                node.val
                    ._Type
                    .eq(&T::OT_TYPE)
                    .then(|| T::extract_mut(&mut node.val._VAL))?,
            ))
        })
}

pub fn compile_trampoline(
    sqvm: NonNull<HSquirrelVM>,
    sq_functions: &SquirrelFunctions,
    ref_func: &SQFunctionProtoB,
    func_name: &str,
    trampoline_name: &str,
) -> Result<SQObject, &'static str> {
    todo!()
}

pub fn as_func_proto(obj: SQObject) -> Result<NonNull<SQFunctionProto>, &'static str> {
    match obj._Type {
        // check if the closure caries any payloads
        SQObjectType::OT_CLOSURE => {
            let closure = unsafe { obj._VAL.asClosure.as_ref().ok_or("null closure")? };

            // how bad could it be :clueless:
            closure
                ._outervalues
                .is_null()
                .then_some(())
                .ok_or("hook cannot be capturing vars")?;

            as_func_proto(closure._function)
        }
        SQObjectType::OT_FUNCPROTO => {
            NonNull::new(unsafe { obj._VAL.asFuncProto }).ok_or("null func proto")
        }
        _ => Err("not a valid function!"),
    }
}

pub fn new_closure(sqvm: NonNull<HSquirrelVM>, proto_func: &SQFunctionProto) -> NonNull<SQClosure> {
    let context = unsafe { sqvm_to_context(sqvm) };
    let closure = unsafe {
        (match context {
            ScriptContext::SERVER => SERVER_FUNCTIONS.wait().sqclosure_new_alloc,
            ScriptContext::CLIENT | ScriptContext::UI => {
                CLIENT_FUNCTIONS.wait().sqclosure_new_alloc
            }
        })(
            sqvm.as_ref().sharedState,
            &mut SQObject {
                _Type: SQFunctionProto::OT_TYPE,
                structNumber: 0,
                _VAL: SQObjectValue {
                    // SAFETY: it's barely safe, but this function here doesn't mutate it, only other stuff down the line does
                    asFuncProto: ptr::from_ref(proto_func).cast_mut(),
                },
            },
        )
    };

    NonNull::new(closure).expect("closure_new_alloc invariant violated")
}

pub fn wrap_in_object<'a, T: IsSQObject<'a>>(val: NonNull<T>) -> SQObject {
    SQObject {
        _Type: T::OT_TYPE,
        structNumber: 0,
        // A bit bad
        _VAL: SQObjectValue {
            asString: val.as_ptr().cast(),
        },
    }
}

pub fn null_sq_object() -> SQObject {
    SQObject {
        _Type: SQObjectType::OT_NULL,
        structNumber: 0,
        _VAL: rrplug::bindings::squirreldatatypes::SQObjectValue {
            asString: std::ptr::null_mut(),
        },
    }
}

// TODO: move this into rrplug
#[inline]
pub fn get_from_sq_string(buf: &rrplug::bindings::squirreldatatypes::SQString) -> Option<&str> {
    str::from_utf8(unsafe {
        std::slice::from_raw_parts(buf._val.as_ptr().cast(), buf.length as usize)
    })
    .ok()
}
