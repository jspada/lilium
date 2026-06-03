use crate::Case;
use syn::{Ident, Stmt, TraitItemFn, Type, TypeParam, parse_quote};

pub fn impl_map(fields: &[(Ident, Type)], var: &TypeParam, name: &Ident) -> TraitItemFn {
    let constructor_fields: Vec<Ident> = fields.iter().map(|(ident, _)| ident.clone()).collect();
    let fields: Vec<Stmt> = Case::process(fields, var)
        .into_iter()
        .map(|(ident, ty)| match ty {
            Case::Var => {
                parse_quote! {
                    let #ident: B = f(&evals.#ident);
                }
            }
            Case::Type(_ty) => {
                todo!()
            }
            Case::VarArray(len) => {
                parse_quote! {
                    let #ident: [_, #len] = &evals.#ident.each_ref().map(|elem| f(elem));
                }
            }
            Case::TypeArray(_ty, _var) => {
                todo!()
            }
        })
        .collect();
    parse_quote! {
        fn map_evals<A, B, M>(evals: &Self::Mles<A>, f: M) -> Self::Mles<B>
        where
            A: Clone + Debug,
            B: Clone + Debug,
            M: Fn(&A) -> B
        {
            #(#fields)*
            #name {
                #(#constructor_fields),*
            }
        }
    }
}

pub fn impl_combine(_fields: &[(Ident, Type)], _var: &TypeParam, _name: &Ident) -> TraitItemFn {
    parse_quote! {
        fn combine<A, B, C, M>(a: &Self::Mles<A>, b: &Self::Mles<B>, f: M) -> Self::Mles<C>
        where
            A: Clone + Debug,
            B: Clone + Debug,
            C: Clone + Debug,
            M: Fn(&A, &B) -> C
        {todo!()}
    }
}

pub fn impl_apply(_fields: &[(Ident, Type)], _var: &TypeParam, _name: &Ident) -> TraitItemFn {
    parse_quote! {
        fn apply<A, M>(a: &mut Self::Mles<A>, f: M)
        where
            A: Clone + Debug,
            M: Fn(&mut A)
        {todo!()}
    }
}

pub fn impl_combine_mut(_fields: &[(Ident, Type)], _var: &TypeParam, _name: &Ident) -> TraitItemFn {
    parse_quote! {
        fn combine_mut_conditional<A, B, M>(
            a: &mut Self::Mles<A>,
            b: &Self::Mles<B>,
            c: Self::Mles<bool>,
            f: M,
        ) where
            A: Clone + Debug,
            B: Clone + Debug,
            M: Fn(&mut A, &B, bool)
        {todo!()}
    }
}

pub fn impl_combine3(_fields: &[(Ident, Type)], _var: &TypeParam, _name: &Ident) -> TraitItemFn {
    parse_quote! {
        fn combine3<A, B, C, M>(a: [&Self::Mles<A>; 2], b: &Self::Mles<B>, f: M) -> Self::Mles<C>
        where
            A: Clone + Debug,
            B: Clone + Debug,
            C: Clone + Debug,
            M: Fn(&A, &A, &B) -> C
        {todo!()}
    }
}
