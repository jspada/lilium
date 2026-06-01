use quote::quote;
use syn::{
    Data, DeriveInput, Fields, GenericParam, Ident, Stmt, TraitItemFn, Type, TypeParam,
    parse_macro_input, parse_quote,
};

#[proc_macro_derive(EvalsCore)]
pub fn derive_evals(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let DeriveInput {
        ident: name,
        generics,
        data,
        ..
    } = input;

    let generic = generics.params.iter().find_map(|generic| {
        if let GenericParam::Type(param) = generic {
            Some(param)
        } else {
            None
        }
    });
    let mut var = generic.expect("expected at least 1 type parameter").clone();
    var.bounds.clear();

    let fields: Vec<(Ident, Type)> = if let Data::Struct(data) = data {
        if let Fields::Named(fields) = data.fields {
            fields
                .named
                .into_iter()
                .map(|field| (field.ident.unwrap(), field.ty))
                .collect()
        } else {
            panic!("only named struct fields allowed");
        }
    } else {
        panic!("only structs allowed");
    };

    let (impl_generics, ty_generics, clause) = generics.split_for_impl();

    let combine = impl_combine(&fields, &var);
    let flatten = impl_flatten(&fields, &var);
    let unflatten = impl_unflatten(&fields, &var);

    let tokens = quote! {
        impl #impl_generics EvalsCore<#var> for #name #ty_generics #clause {
            #combine
            #flatten
            #unflatten

            // fn unflatten(elems: &mut IntoIter<V>) -> Self {
                // todo!();
            // }
        }
    };
    proc_macro::TokenStream::from(tokens)
}

fn is_var(ty: &Type, var: &TypeParam) -> bool {
    if let Type::Path(path) = ty {
        path.path.is_ident(&var.ident)
    } else {
        false
    }
}

fn impl_combine(fields: &[(Ident, Type)], var: &TypeParam) -> TraitItemFn {
    let constructor_fields: Vec<Ident> = fields.iter().map(|(ident, _)| ident.clone()).collect();
    let fields: Vec<Stmt> = fields
        .iter()
        .map(|(ident, ty)| {
            if is_var(ty, var) {
                parse_quote! {
                    let #ident: #ty = f(&self.#ident, &other.#ident);
                }
            } else {
                unimplemented!()
            }
        })
        .collect();
    parse_quote! {
        fn combine<C: Fn(&V, &V) -> V>(&self, other: &Self, f: C) -> Self {
            #(#fields)*
            Self {
                #(#constructor_fields),*
            }
        }
    }
}

fn impl_flatten(fields: &[(Ident, Type)], var: &TypeParam) -> TraitItemFn {
    let fields: Vec<Stmt> = fields
        .iter()
        .map(|(ident, ty)| {
            if is_var(ty, var) {
                parse_quote! {
                    vec.push(self.#ident);
                }
            } else {
                unimplemented!()
            }
        })
        .collect();
    parse_quote! {
        fn flatten(self, vec: &mut Vec<V>) {
            #(#fields)*
        }
    }
}

fn impl_unflatten(fields: &[(Ident, Type)], var: &TypeParam) -> TraitItemFn {
    let constructor_fields: Vec<Ident> = fields.iter().map(|(ident, _)| ident.clone()).collect();
    let fields: Vec<Stmt> = fields
        .iter()
        .map(|(ident, ty)| {
            if is_var(ty, var) {
                parse_quote! {
                    let #ident: #ty = elems.next().unwrap();
                }
            } else {
                unimplemented!()
            }
        })
        .collect();
    parse_quote! {
        fn unflatten(elems: &mut IntoIter<V>) -> Self {
            #(#fields)*
            Self {
                #(#constructor_fields),*
            }
        }
    }
}
