use crate::is_var;
use syn::{Ident, Stmt, TraitItemFn, Type, TypeParam, parse_quote};

pub fn impl_combine(fields: &[(Ident, Type)], var: &TypeParam) -> TraitItemFn {
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

pub fn impl_flatten(fields: &[(Ident, Type)], var: &TypeParam) -> TraitItemFn {
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

pub fn impl_unflatten(fields: &[(Ident, Type)], var: &TypeParam) -> TraitItemFn {
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
