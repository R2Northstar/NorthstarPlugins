use core::{slice, str};
use high::squirrel_traits::IsSQObject;
use rrplug::{
    bindings::squirreldatatypes::{
        SQClosure, SQFunctionProto, SQNativeClosure, SQObject,
        SQObjectType::{self, OT_NULL},
        SQObjectValue, SQString, SQTable, StringTable,
    },
    high::{squirrel::SQHandle, squirrel_traits::GetFromSQObject},
    mid::squirrel::sqvm_to_context,
    prelude::*,
};
use std::{
    ffi::{CStr, CString},
    mem,
    ptr::NonNull,
    str::FromStr,
};

use crate::bindings::{
    CLIENT_FUNCTIONS, SERVER_FUNCTIONS, SQFunctionProtoB, SQInstruction, SQOpCodes, SQTypeGroup,
    SQTypeValue, TypeDescriptor,
};

pub fn get_native_function(
    sqvm: NonNull<HSquirrelVM>,
    name: &str,
) -> Option<NonNull<SQNativeClosure>> {
    let table = unsafe { sqvm.as_ref().sharedState.as_ref()?._nativeClosures.as_ref() };
    ty_filter::<SQNativeClosure>(table)
        .filter_map(|(key, closure)| Some((SQHandle::<SQString>::try_new(*key).ok()?, closure)))
        .find_map(|(key, closure)| {
            get_from_sq_string(key.get())
                .filter(|cmp_name| *cmp_name == name)
                .or_else(|| unsafe {
                    closure
                        ._name
                        .as_ref()
                        .and_then(|name| get_from_sq_string(name))
                        .filter(|cmp_name| *cmp_name == name)
                })
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
    org_proto: &SQFunctionProtoB,
    function_id: &str,
    trampoline_name: &str,
) -> Result<(NonNull<SQClosure>, NonNull<SQFunctionProto>), &'static str> {
    if org_proto.nDefaultParams > 0 {
        Err("default params are unsupported")?;
    }
    if org_proto.otherVarInfoSize > 0 {
        Err("outer values are unsupported")?;
    }

    let hook_call = get_native_function(sqvm, trampoline_name)
        .ok_or("couldn't find the native trampoline function!")?;
    let function_id =
        CString::new(function_id).map_err(|_| "failed to convert trampoline_name to a cstring")?;
    let actual_arg_count = org_proto.nParameters.saturating_sub(1); // since we skip root table

    let context = unsafe { sqvm_to_context(sqvm) };
    // SAFETY: should be the correct function getting called
    let mut trampoline = NonNull::new(unsafe {
        (match context {
            ScriptContext::SERVER => SERVER_FUNCTIONS.wait().sqfunctionproto_create,
            ScriptContext::CLIENT | ScriptContext::UI => {
                CLIENT_FUNCTIONS.wait().sqfunctionproto_create
            }
        })(
            sqvm.as_ref().sharedState,
            3 + (actual_arg_count % 2) + (actual_arg_count / 2), // instructions OP_LOAD + a combo of OP_DMOVE/OP_MOVE + OP_FASTCALL_NATIVE + OP_RETURN
            1,                     // literals; will be the only string
            org_proto.nParameters, // number of parameters
            1,                     // functions; will be the native function for the trampoline
            0,                     // unknown_C8,
            0,                     // nothervarinfo; unsupported
            0,                     // won't be providing line info
            org_proto.nParameters, // number of locals matches the number of parameters; they are also inserted in reverse
            0,                     // ndefaultparams; unsupported for now
            0,                     // param_11; yeah no clue but 0
        )
    })
    .ok_or("sqfunctionproto_create returned a null proto func")?;
    // SAFETY: we own the trampoline
    let trampoline_ref = unsafe { trampoline.as_mut() };

    // SAFETY: the allocator in the create functions should have allocated enough space
    let instructions_buffer = unsafe {
        slice::from_raw_parts_mut(
            trampoline_ref.instruction.as_mut_ptr(),
            trampoline_ref.skippedInstruction.arg2 as usize,
        )
    };

    instructions_buffer[0] = SQInstruction {
        op: SQOpCodes::OP_LOAD,
        arg1: 0,                           // load from 0-th literal?
        output: org_proto.nParameters + 1, // the stack is filled by org_proto.nParameters so + 1 and org_proto.nParameters on the stack is the return value for call
        arg2: 0,
        arg3: 0,
    };
    // since we have at least 3 instructions this will always work
    instructions_buffer[instructions_buffer.len() - 2] = SQInstruction {
        op: SQOpCodes::OP_FASTCALL_NATIVE,
        arg1: 0,                                   // load from 0-th function?
        output: org_proto.nParameters, // org_proto.nParameters on the stack is the return value for call
        arg2: org_proto.nParameters as i16, // new stack base; hopefully correct
        arg3: org_proto.nParameters as i16 + 1i16, // seemingly this is how many arguments the native function wants
    };
    instructions_buffer[instructions_buffer.len() - 1] = SQInstruction {
        op: SQOpCodes::OP_RETURN,
        arg1: org_proto.nParameters, // use return value from OP_FASTCALL_NATIVE
        output: 1, // I think this is correct? since root table is 0 then return value is 1
        arg2: 0,
        arg3: 0,
    };

    instructions_buffer
        .iter_mut()
        .skip(1) // skip the load
        .zip((0..actual_arg_count).array_chunks::<2>())
        .for_each(|(ins, [first, second])| {
            *ins = SQInstruction {
                op: SQOpCodes::OP_DMOVE,
                arg1: 1 + first,                               // skip root table
                output: 1 + 1 + org_proto.nParameters + first, // skip root table + account for return slot
                arg2: (1 + 1 + org_proto.nParameters + second) as i16, // skip root table + account for return slot + second arg
                arg3: (1 + second) as i16, // skip root table + second arg
            }
        });

    // if it's not even add a load instruction
    if actual_arg_count % 2 == 1 {
        instructions_buffer[instructions_buffer.len() - 3] = SQInstruction {
            op: SQOpCodes::OP_MOVE,
            arg1: org_proto.nParameters - 1, // last arg
            output: 1 + org_proto.nParameters + actual_arg_count, // I think this is correct?
            arg2: 0,
            arg3: 0,
        };
    }

    // set first function
    unsafe {
        *trampoline
            .as_mut()
            ._functions
            .as_mut()
            .ok_or("sqfunctionproto_create failed to allocate functions")? =
            wrap_in_object::<SQNativeClosure>(hook_call);
    }

    let literal = new_sqstring(
        context,
        unsafe { sqvm.as_ref().sharedState.as_ref().ok_or("no shared state") }?._stringTable,
        &function_id,
    );

    // insert literal for the function id
    unsafe {
        *trampoline
            .as_mut()
            .literals
            .as_mut()
            .ok_or("sqfunctionproto_create failed to allocate literals")? =
            increment_ref_sqobject(literal.take_obj());
    }

    log::info!("hook created with {instructions_buffer:?}");

    // insert parameters variables
    let string_table =
        unsafe { sqvm.as_ref().sharedState.as_ref().ok_or("no shared state") }?._stringTable;
    let parameters = unsafe {
        slice::from_raw_parts_mut(
            trampoline.as_ref()._parameters,
            trampoline.as_ref().nParameters as usize,
        )
    };
    parameters.iter_mut().enumerate().for_each(|(i, param)| {
        *param = if i == 0 {
            new_sqstring(context, string_table, c"this").take_obj()
        } else {
            let name = "param".to_string() + &i.to_string() + "\0";
            increment_ref_sqobject(
                new_sqstring(
                    context,
                    string_table,
                    CStr::from_bytes_with_nul(name.as_bytes()).unwrap_or(c"param"),
                )
                .take_obj(),
            )
        }
    });

    // insert stack variables
    const VAR_TYPE_DESCRIPTOR: TypeDescriptor = TypeDescriptor {
        group: SQTypeGroup::TyPrimitive,
        type_hash: 42391, // not sure how to actually generate this
        base: SQTypeValue {
            prim_type: SQObjectType::OT_NULL,
        },
    };
    unsafe {
        slice::from_raw_parts_mut(
            trampoline.as_ref().localVarInfos,
            trampoline.as_ref().localVarInfoSize as usize,
        )
    }
    .iter_mut()
    .zip((0..org_proto.nParameters).rev())
    .for_each(|(local, i)| {
        *local = crate::bindings::SQLocalVarInfo {
            name: parameters
                .get(i as usize)
                .copied()
                .map(increment_ref_sqobject)
                .unwrap_or_else(null_sq_object),
            type_descriptor: &VAR_TYPE_DESCRIPTOR, // copied from the previous trampoline compiler; could it be the sq type?
            _start_op: 0,
            _end_op: (instructions_buffer.len() - 1) as i32,
            stackpos: i,
            dword24: -1, // copied from the previous trampoline compiler
        }
    });

    unsafe {
        trampoline.as_mut().funcName = increment_ref_sqobject(wrap_in_object(NonNull::from_mut(
            new_sqstring(context, string_table, c"TRAMPOLINE").get_mut(),
        )));
        trampoline.as_mut().fileName = increment_ref_sqobject(wrap_in_object(NonNull::from_mut(
            new_sqstring(context, string_table, c"sqhooks/src/utils.rs").get_mut(),
        )));
    }

    Ok((
        new_closure(sqvm, unsafe {
            trampoline.cast::<SQFunctionProto>().as_ref()
        }),
        trampoline.cast::<SQFunctionProto>(),
    ))
}

pub fn _compile_trampoline(
    sqvm: NonNull<HSquirrelVM>,
    sq_functions: &SquirrelFunctions,
    ref_func: &SQFunctionProtoB,
    function_id: &str,
    trampoline_name: &str,
) -> Result<(NonNull<SQClosure>, NonNull<SQFunctionProto>), &'static str> {
    let args = (1..ref_func.nParameters)
        .map(|i| "var a".to_string() + &i.to_string() + ",")
        .collect::<String>();
    let args = args.strip_suffix(",").unwrap_or(&args);

    let args_untyped = (1..ref_func.nParameters)
        .map(|i| "a".to_string() + &i.to_string() + ",")
        .collect::<String>();
    let args_untyped = args_untyped.strip_suffix(",").unwrap_or(&args_untyped);

    let code = format!(
        r#"__EXTRACT(var function ({args}) {{return {trampoline_name}("{function_id}"{} {args_untyped})}})"#,
        if ref_func.nParameters == 1 { ' ' } else { ',' }
    );
    log::warn!("{code}");
    if let Err(err) = high::squirrel::compile_string(sqvm, sq_functions, true, code) {
        err.log();
        return Err("failed to compile trampoline");
    };

    if unsafe { (sq_functions.sq_newtable)(sqvm.as_ptr()) }
        == rrplug::bindings::squirrelclasstypes::SQRESULT::SQRESULT_ERROR
    {
        return Err("failed to create tmp table");
    }

    let (mut trampoline, mut closure_trampoline) = unsafe {
        let sqclosure = NonNull::from_mut(
            crate::hook_install::EXTRACT
                .lock()
                .entry(sqvm_to_context(sqvm))
                .or_default()
                .take()
                .ok_or("found none sqclosure sqobject")?
                .take()
                .as_mut()
                .ok_or("found null sqclosure sqobject")?,
        );

        (as_func_proto(wrap_in_object(sqclosure))?, sqclosure)
    };

    // increment ref count
    unsafe { closure_trampoline.as_mut().uiRef += 1 };
    unsafe { trampoline.as_mut().uiRef += 1 };

    Ok((closure_trampoline, trampoline))
}

pub fn clone_func_name(org: &SQFunctionProtoB, dst: &mut SQFunctionProtoB) {
    if org.fileName._Type == SQString::OT_TYPE && dst.fileName._Type == OT_NULL {
        dst.fileName = org.fileName;
        // SAFETY: checked that the type is valid
        if let Some(file_name) = unsafe { dst.fileName._VAL.asString.as_mut() } {
            file_name.uiRef += 1;
        }
    }
    if org.funcName._Type == SQString::OT_TYPE && dst.funcName._Type == OT_NULL {
        dst.funcName = org.funcName;
        // SAFETY: checked that the type is valid
        if let Some(file_name) = unsafe { dst.funcName._VAL.asString.as_mut() } {
            file_name.uiRef += 1;
        }
    }
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
            &mut wrap_in_object(NonNull::from_ref(proto_func)),
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

pub fn new_sqstring<'a>(
    context: ScriptContext,
    string_table: *mut StringTable,
    str: &'a CStr,
) -> SQHandle<'a, SQString> {
    let mut sqstring = NonNull::new(unsafe {
        (match context {
            ScriptContext::SERVER => SERVER_FUNCTIONS.wait().sqstringtable_add,
            ScriptContext::CLIENT | ScriptContext::UI => CLIENT_FUNCTIONS.wait().sqstringtable_add,
        })(string_table, str.as_ptr(), str.count_bytes() as u64)
    })
    .expect("string table should always return a valid sqstring");

    unsafe { sqstring.as_mut().uiRef += 1 };

    SQHandle::try_new(wrap_in_object(sqstring)).expect("this is a sqstring")
}

pub fn increment_ref_sqobject(obj: SQObject) -> SQObject {
    if (obj._Type as u32 & SQObjectType::SQOBJECT_REF_COUNTED as u32)
        != SQObjectType::SQOBJECT_REF_COUNTED as u32
    {
        return obj;
    }

    if let Some(refcounted) = unsafe { obj._VAL.asString.as_mut() } {
        refcounted.uiRef += 1;
    }

    obj
}

pub fn free_sqobject(obj: SQObject) {
    if (obj._Type as u32 & SQObjectType::SQOBJECT_REF_COUNTED as u32)
        != SQObjectType::SQOBJECT_REF_COUNTED as u32
    {
        return;
    }

    if let Some(refcounted) = unsafe { obj._VAL.asString.as_mut() } {
        refcounted.uiRef -= 1;

        if refcounted.uiRef <= 0 {
            // destructor in the v table
            let destructor = unsafe {
                mem::transmute::<*mut std::ffi::c_void, extern "C" fn(*mut ())>(
                    refcounted.vftable.add(1),
                )
            };

            destructor((refcounted as *mut SQString).cast())
        }
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

pub fn print_sqobject(
    &SQObject {
        _Type,
        structNumber: _,
        _VAL,
    }: &SQObject,
) {
    match _Type {
        SQObjectType::OT_USERPOINTER => log::info!("{:?}", SQObjectType::OT_USERPOINTER),
        SQObjectType::OT_VECTOR => log::info!("{:?}", SQObjectType::OT_VECTOR),
        SQObjectType::OT_NULL => log::info!("{:?}", SQObjectType::OT_NULL),
        SQObjectType::OT_BOOL => {
            log::info!("{:?}: {}", SQObjectType::OT_BOOL, unsafe { _VAL.asInteger })
        }
        SQObjectType::OT_INTEGER => log::info!("{:?}: {}", SQObjectType::OT_INTEGER, unsafe {
            _VAL.asInteger
        }),
        SQObjectType::OT_FLOAT => {
            log::info!("{:?}: {}", SQObjectType::OT_FLOAT, unsafe { _VAL.asFloat })
        }
        SQObjectType::OT_STRING => log::info!(
            "{:?}: {:?}",
            SQObjectType::OT_STRING,
            get_from_sq_string(unsafe { _VAL.asString.as_ref().unwrap() })
        ),
        SQObjectType::OT_ARRAY => log::info!("{:?}", SQObjectType::OT_ARRAY),
        SQObjectType::OT_CLOSURE => log::info!("{:?}", SQObjectType::OT_CLOSURE),
        SQObjectType::OT_NATIVECLOSURE => log::info!("{:?}", SQObjectType::OT_NATIVECLOSURE),
        SQObjectType::OT_ASSET => log::info!(
            "{:?}: {:?}",
            SQObjectType::OT_ASSET,
            get_from_sq_string(unsafe { _VAL.asString.as_ref().unwrap() })
        ),
        SQObjectType::OT_THREAD => log::info!("{:?}", SQObjectType::OT_THREAD),
        SQObjectType::OT_FUNCPROTO => log::info!("{:?}", SQObjectType::OT_FUNCPROTO),
        SQObjectType::OT_CLASS => log::info!("{:?}", SQObjectType::OT_CLASS),
        SQObjectType::OT_STRUCT => log::info!("{:?}", SQObjectType::OT_STRUCT),
        SQObjectType::OT_WEAKREF => log::info!("{:?}", SQObjectType::OT_WEAKREF),
        SQObjectType::OT_TABLE => log::info!("{:?}", SQObjectType::OT_TABLE),
        SQObjectType::OT_USERDATA => log::info!("{:?}", SQObjectType::OT_USERDATA),
        SQObjectType::OT_INSTANCE => log::info!("{:?}", SQObjectType::OT_INSTANCE),
        SQObjectType::OT_ENTITY => log::info!("{:?}", SQObjectType::OT_ENTITY),
        _ => log::info!("unknown"),
    }
}

pub struct CheckedString<'a>(SQHandle<'a, SQString>);

impl<'a> GetFromSQObject for CheckedString<'a> {
    #[inline]
    fn get_from_sqobject(obj: &SQObject) -> Self {
        match SQHandle::try_new(*obj) {
            Ok(handle) => CheckedString(handle),
            Err(_) => {
                panic!(
                    "the object wasn't the correct type got {:X} expected {}",
                    obj._Type as i32,
                    std::any::type_name::<String>()
                );
            }
        }
    }
}
