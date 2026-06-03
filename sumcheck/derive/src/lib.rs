use evals_core::{impl_combine, impl_flatten, impl_unflatten};
use quote::quote;
use syn::{
    Data, DeriveInput, Expr, Fields, GenericParam, Ident, Type, TypeParam, parse_macro_input,
};

mod evals;
mod evals_core;

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

    let map_evals = evals::impl_map(&fields, &var, &name);
    let evals_combine = evals::impl_combine(&fields, &var, &name);
    let apply = evals::impl_apply(&fields, &var);
    let combine_mut = evals::impl_combine_mut(&fields, &var, &name);
    let combine3 = evals::impl_combine3(&fields, &var, &name);

    let tokens = quote! {
        impl #impl_generics EvalsCore<#var> for #name #ty_generics #clause {
            #combine
            #flatten
            #unflatten
        }

        impl Evals for #name<()> #clause {
            type Mles<V: Clone + Debug> = #name<V>;

            #map_evals
            #evals_combine
            #apply
            #combine_mut
            #combine3
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

enum Case {
    Var,
    Type(Type),
    VarArray(Expr),
    TypeArray(Type, Expr),
}

impl Case {
    fn process(fields: &[(Ident, Type)], var: &TypeParam) -> Vec<(Ident, Self)> {
        fields
            .iter()
            .map(|(ident, ty)| {
                let ty: Self = match (is_var(ty, var), ty) {
                    (true, _) => Case::Var,
                    (false, Type::Array(ty)) => {
                        if is_var(&ty.elem, var) {
                            Case::VarArray(ty.len.clone())
                        } else {
                            Case::TypeArray(*ty.elem.clone(), ty.len.clone())
                        }
                    }
                    (false, ty) => Case::Type(ty.clone()),
                };
                (ident.clone(), ty)
            })
            .collect()
    }
}
