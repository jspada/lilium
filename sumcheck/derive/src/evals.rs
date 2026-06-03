use crate::Case;
use syn::{
    GenericArgument, Ident, PathArguments, PathSegment, Stmt, TraitItemFn, Type, TypeParam,
    parse_quote,
};

fn substitute(ty: &Type, from: &Ident, to: &Type) -> Type {
    match ty.clone() {
        Type::Array(mut type_array) => {
            let ty = &type_array.elem;
            let ty = substitute(ty, from, to);
            type_array.elem = Box::new(ty);
            Type::Array(type_array)
        }
        Type::Paren(mut type_paren) => {
            let ty = substitute(&type_paren.elem, from, to);
            type_paren.elem = Box::new(ty);
            Type::Paren(type_paren)
        }
        Type::Path(mut type_path) => {
            if let Some(PathSegment {
                ident: _,
                arguments: PathArguments::AngleBracketed(args),
            }) = type_path.path.segments.last_mut()
            {
                for arg in args.args.iter_mut() {
                    if let GenericArgument::Type(Type::Path(path)) = arg
                        && path.path.is_ident(from)
                    {
                        *arg = GenericArgument::Type(to.clone());
                    }
                }
            }
            Type::Path(type_path)
        }
        Type::Tuple(mut type_tuple) => {
            for elem in type_tuple.elems.iter_mut() {
                let ty = substitute(elem, from, to);
                *elem = ty;
            }
            Type::Tuple(type_tuple)
        }
        ty => ty,
    }
}

pub fn impl_map(fields: &[(Ident, Type)], var: &TypeParam, name: &Ident) -> TraitItemFn {
    let constructor_fields: Vec<Ident> = fields.iter().map(|(ident, _)| ident.clone()).collect();
    let generic_b: Type = parse_quote!(B);
    let unit: Type = parse_quote!(());
    let fields: Vec<Stmt> = Case::process(fields, var)
        .into_iter()
        .map(|(ident, ty)| match ty {
            Case::Var => {
                parse_quote! {
                    let #ident: B = f(&evals.#ident);
                }
            }
            Case::Type(ty) => {
                let instance = substitute(&ty, &var.ident, &unit);
                let ty = substitute(&ty, &var.ident, &generic_b);
                parse_quote! {
                    let #ident: #ty = <#instance>::map_evals(&evals.#ident, &f);
                }
            }
            Case::VarArray(len) => {
                parse_quote! {
                    let #ident: [B; #len] = evals.#ident.each_ref().map(&f);
                }
            }
            Case::TypeArray(ty, len) => {
                let instance = substitute(&ty, &var.ident, &unit);
                let ty = substitute(&ty, &var.ident, &generic_b);
                parse_quote! {
                    let #ident: [#ty; #len] = evals.#ident.each_ref().map(|elem| {
                        <#instance>::map_evals(elem, &f)
                    });
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

pub fn impl_combine(fields: &[(Ident, Type)], var: &TypeParam, name: &Ident) -> TraitItemFn {
    let constructor_fields: Vec<Ident> = fields.iter().map(|(ident, _)| ident.clone()).collect();
    let generic_c: Type = parse_quote!(C);
    let unit: Type = parse_quote!(());
    //
    let fields: Vec<Stmt> = Case::process(fields, var)
        .into_iter()
        .map(|(ident, ty)| match ty {
            Case::Var => {
                parse_quote! {
                    let #ident: C = f(&a.#ident, &b.#ident);
                }
            }
            Case::Type(ty) => {
                let instance = substitute(&ty, &var.ident, &unit);
                let ty = substitute(&ty, &var.ident, &generic_c);
                parse_quote! {
                    let #ident: #ty = <#instance as Evals>::combine(&a.#ident, &b.#ident, &f);
                }
            }
            Case::VarArray(len) => {
                parse_quote! {
                    let #ident: [C; #len] = {
                        let mut b = b.#ident.iter();
                        a.#ident.each_ref().map(|a| f(a, b.next().unwrap()))
                    };
                }
            }
            Case::TypeArray(ty, len) => {
                let instance = substitute(&ty, &var.ident, &unit);
                let ty = substitute(&ty, &var.ident, &generic_c);
                parse_quote! {
                    let #ident: [#ty; #len] = {
                        let mut b = b.#ident.iter();
                        a.#ident.each_ref().map(|a| {
                            let b = b.next().unwrap();
                            <#instance as Evals>::combine(a, b, &f)
                        })
                    };
                }
            }
        })
        .collect();

    parse_quote! {
        fn combine<A, B, C, M>(a: &Self::Mles<A>, b: &Self::Mles<B>, f: M) -> Self::Mles<C>
        where
            A: Clone + Debug,
            B: Clone + Debug,
            C: Clone + Debug,
            M: Fn(&A, &B) -> C
        {
            #(#fields)*
            #name {
                #(#constructor_fields),*
            }
        }
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
