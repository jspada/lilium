use crate::is_var;
use syn::{Expr, Ident, Stmt, TraitItemFn, Type, TypeParam, parse_quote};

enum Case {
    Var,
    Type(Type),
    Array(Type, Expr),
}

impl Case {
    fn process(fields: &[(Ident, Type)], var: &TypeParam) -> Vec<(Ident, Self)> {
        fields
            .iter()
            .map(|(ident, ty)| {
                let is_var = is_var(ty, var);
                let ty: Self = match (is_var, ty) {
                    (true, _) => Case::Var,
                    (false, Type::Array(ty)) => Case::Array(*ty.elem.clone(), ty.len.clone()),
                    (false, ty) => Case::Type(ty.clone()),
                };
                (ident.clone(), ty)
            })
            .collect()
    }
}

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
            Case::Array(ty, len) => {
                parse_quote! {
                    let #ident: [#ty, #len] = &evals.#ident.each_ref().map(|elem| f(elem));
                }
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
