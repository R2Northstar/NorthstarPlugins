use rrplug::{
    bindings::squirreldatatypes::{SQObject, SQObjectType},
    high::squirrel_traits::{GetFromSquirrelVm, PushToSquirrelVm, SQVMName},
    prelude::*,
};
use std::marker::PhantomData;

#[derive(Debug)]
pub(crate) struct Variadic<'a, T> {
    pub vargs: Vec<T>,
    pub(crate) phantom: PhantomData<*mut &'a mut T>,
}

impl<'a, T: GetFromSquirrelVm> GetFromSquirrelVm for Variadic<'a, T> {
    fn get_from_sqvm(
        _sqvm: std::ptr::NonNull<HSquirrelVM>,
        _sqfunctions: &'static SquirrelFunctions,
        _stack_pos: i32,
    ) -> Self {
        unimplemented!("don't use this api directly!")
    }

    fn get_from_sqvm_internal(
        sqvm: std::ptr::NonNull<HSquirrelVM>,
        sqfunctions: &'static SquirrelFunctions,
        stack_pos: &mut i32,
    ) -> Self {
        let start = *stack_pos;
        let end = (start..)
            .find(|i| SQObject::get_from_sqvm(sqvm, sqfunctions, *i)._Type == SQObjectType::OT_NULL)
            .expect("there has to be a OT_NULL somewhere");

        *stack_pos = i32::MAX; // to prevent other args to be fetched from after this
        Self {
            vargs: (start..end)
                .map(|i| T::get_from_sqvm(sqvm, sqfunctions, i))
                .collect(),
            phantom: PhantomData,
        }
    }
}

impl<'a, T: PushToSquirrelVm> PushToSquirrelVm for Variadic<'a, T> {
    const DEFAULT_RESULT: rrplug::bindings::squirrelclasstypes::SQRESULT =
        panic!("cannot return this");

    fn push_to_sqvm(self, sqvm: std::ptr::NonNull<HSquirrelVM>, sqfunctions: &SquirrelFunctions) {
        for arg in self.vargs {
            arg.push_to_sqvm(sqvm, sqfunctions);
        }
    }
}
impl<'a, T: SQVMName> SQVMName for Variadic<'a, T> {
    fn get_sqvm_name() -> String {
        T::get_sqvm_name() + " arg, ..."
    }
}
