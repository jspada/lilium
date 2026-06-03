use crate::Case;
use syn::{Ident, Stmt, TraitItemFn, Type, TypeParam, parse_quote};

pub fn impl_combine(fields: &[(Ident, Type)], var: &TypeParam) -> TraitItemFn {
    let constructor_fields: Vec<Ident> = fields.iter().map(|(ident, _)| ident.clone()).collect();
    let fields: Vec<Stmt> = Case::process(fields, var)
        .into_iter()
        .map(|(ident, ty)| match ty {
            Case::Var => {
                parse_quote! {
                    let #ident: #var = f(&self.#ident, &other.#ident);
                }
            }
            Case::Type(ty) => {
                parse_quote! {
                    let #ident: #ty = self.#ident.combine(&other.#ident, f);
                }
            }
            Case::VarArray(len) => {
                parse_quote! {
                    let #ident: [#var; #len] = {
                        let mut other = other.#ident.iter();
                        self.#ident.each_ref().map(|a| f(a, other.next().unwrap()))
                    };
                }
            }
            Case::TypeArray(_, _expr) => todo!(),
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
    let fields: Vec<Stmt> = Case::process(fields, var)
        .iter()
        .map(|(ident, ty)| match ty {
            Case::Var => {
                parse_quote! {
                    vec.push(self.#ident);
                }
            }
            Case::Type(_) => {
                parse_quote! {
                    self.#ident.flatten(vec);
                }
            }
            Case::VarArray(_len) => {
                parse_quote! {
                    vec.extend(self.#ident);
                }
            }
            Case::TypeArray(_, _len) => todo!(),
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
    let fields = Case::process(fields, var);
    let fields: Vec<Stmt> = fields
        .iter()
        .map(|(ident, ty)| match ty {
            Case::Var => {
                parse_quote! {
                    let #ident: #var = elems.next().unwrap();
                }
            }
            Case::Type(ty) => {
                parse_quote! {
                    let #ident: #ty = <#ty>::unflatten(elems);
                }
            }
            Case::VarArray(len) => {
                parse_quote! {
                    let #ident: [#var; #len] = {
                        let #ident: Vec<#var> = elems.by_ref().take(#len).collect();
                        #ident.try_into().unwrap()
                    };
                }
            }
            Case::TypeArray(_, _len) => todo!(),
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
