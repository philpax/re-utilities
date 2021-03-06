use syn::parse::{Parse, ParseStream, Result};
use syn::punctuated::Punctuated;
use syn::{braced, bracketed, parenthesized, Token};

use super::grammar::*;

#[cfg(test)]
mod tests;

mod kw {
    syn::custom_keyword!(meta);
    syn::custom_keyword!(address);
    syn::custom_keyword!(functions);
}

impl Parse for Ident {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Ident(input.parse::<syn::Ident>()?.to_string()))
    }
}

fn parse_type_ident(input: ParseStream) -> Result<String> {
    // dodgy hack to "support" generics for now
    let ident: syn::Ident = input.parse()?;
    let mut name = ident.to_string();

    loop {
        if input.peek(syn::Token![<]) {
            input.parse::<syn::Token![<]>()?;
            name += "<";
        } else if input.peek(syn::Ident) {
            let ident: syn::Ident = input.parse()?;
            name += &ident.to_string();
        } else if input.peek(syn::Token![>]) {
            input.parse::<syn::Token![>]>()?;
            name += ">";
        } else {
            break Ok(name);
        }
    }
}

impl Parse for ItemPath {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut item_path = ItemPath::empty();
        loop {
            // todo: make parsing stricter so that this takes idents
            // separated by double-colons that end in a type, not just
            // all types
            // that is to say, `use lol<lol>::lol` should not parse, but
            // `use lol::lol<lol>` should
            if input.peek(syn::Ident) {
                item_path.push(parse_type_ident(input)?.into());
            } else if input.peek(syn::Token![::]) {
                input.parse::<syn::Token![::]>()?;
            } else if input.peek(syn::Token![super]) {
                return Err(input.error("super not supported"));
            } else {
                break;
            }
        }
        return Ok(item_path);
    }
}

impl Parse for Type {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(syn::Ident) {
            Ok(Type::Ident(parse_type_ident(input)?.as_str().into()))
        } else if lookahead.peek(syn::Token![*]) {
            input.parse::<syn::Token![*]>()?;

            let lookahead = input.lookahead1();
            if lookahead.peek(syn::Token![const]) {
                input.parse::<syn::Token![const]>()?;
                Ok(Type::ConstPointer(Box::new(input.parse()?)))
            } else if lookahead.peek(syn::Token![mut]) {
                input.parse::<syn::Token![mut]>()?;
                Ok(Type::MutPointer(Box::new(input.parse()?)))
            } else {
                Err(lookahead.error())
            }
        } else {
            Err(lookahead.error())
        }
    }
}

impl Parse for MacroCall {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: Ident = input.parse()?;
        input.parse::<Token![!]>()?;

        let content;
        parenthesized!(content in input);

        let arguments: Punctuated<_, Token![,]> = content.parse_terminated(Expr::parse)?;
        let arguments = Vec::from_iter(arguments.into_iter());

        Ok(MacroCall { name, arguments })
    }
}

impl Parse for Expr {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(syn::Ident) {
            if input.peek2(syn::Token![!]) {
                Ok(Expr::Macro(input.parse()?))
            } else {
                Ok(Expr::Ident(input.parse()?))
            }
        } else if lookahead.peek(syn::LitInt) {
            let lit: syn::LitInt = input.parse()?;
            Ok(Expr::IntLiteral(lit.base10_parse()?))
        } else if lookahead.peek(syn::LitStr) {
            let lit: syn::LitStr = input.parse()?;
            Ok(Expr::StringLiteral(lit.value()))
        } else {
            Err(lookahead.error())
        }
    }
}

impl Parse for Attribute {
    fn parse(input: ParseStream) -> Result<Self> {
        input.parse::<syn::Token![#]>()?;

        let content;
        bracketed!(content in input);

        let name = content.parse()?;

        let content2;
        parenthesized!(content2 in content);

        let arguments: Punctuated<_, Token![,]> = content2.parse_terminated(Expr::parse)?;
        let arguments = Vec::from_iter(arguments.into_iter());

        Ok(Attribute::Function(name, arguments))
    }
}

impl Parse for Argument {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(syn::Token![&]) {
            input.parse::<syn::Token![&]>()?;

            let lookahead = input.lookahead1();
            if lookahead.peek(syn::Token![mut]) {
                input.parse::<syn::Token![mut]>()?;
                input.parse::<syn::Token![self]>()?;

                Ok(Argument::MutSelf)
            } else if lookahead.peek(syn::Token![self]) {
                input.parse::<syn::Token![self]>()?;

                Ok(Argument::ConstSelf)
            } else {
                Err(lookahead.error())
            }
        } else if lookahead.peek(syn::Ident) {
            Ok(Argument::Field(input.parse()?))
        } else {
            Err(lookahead.error())
        }
    }
}

impl Parse for Function {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut attributes = vec![];
        while input.peek(syn::Token![#]) {
            attributes.push(input.parse()?);
        }

        input.parse::<syn::Token![fn]>()?;
        let name: Ident = input.parse()?;

        let content;
        parenthesized!(content in input);

        let arguments: Punctuated<_, Token![,]> = content.parse_terminated(Argument::parse)?;
        let arguments = Vec::from_iter(arguments.into_iter());

        let return_type = if input.peek(syn::Token![->]) {
            input.parse::<syn::Token![->]>()?;
            Some(input.parse()?)
        } else {
            None
        };

        Ok(Function {
            name,
            attributes,
            arguments,
            return_type,
        })
    }
}

impl Parse for TypeRef {
    fn parse(input: ParseStream) -> Result<Self> {
        use syn::parse::discouraged::Speculative;

        let ahead = input.fork();
        if let Ok(macro_call) = ahead.call(MacroCall::parse) {
            input.advance_to(&ahead);
            Ok(TypeRef::Macro(macro_call))
        } else {
            Ok(TypeRef::Type(input.parse()?))
        }
    }
}

impl Parse for ExprField {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        Ok(ExprField(name, input.parse()?))
    }
}

impl Parse for TypeField {
    fn parse(input: ParseStream) -> Result<Self> {
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        Ok(TypeField(name, input.parse()?))
    }
}

fn parse_optionally_braced_content<T>(
    input: ParseStream,
    content_parser: fn(ParseStream) -> Result<T>,
) -> Result<Vec<T>> {
    if input.peek(syn::token::Brace) {
        let content;
        braced!(content in input);

        let fields: Punctuated<_, Token![,]> = content.parse_terminated(content_parser)?;
        Ok(Vec::from_iter(fields.into_iter()))
    } else {
        Ok(vec![content_parser(input)?])
    }
}

impl Parse for TypeStatement {
    fn parse(input: ParseStream) -> Result<Self> {
        use syn::parse::discouraged::Speculative;

        let lookahead = input.lookahead1();
        if lookahead.peek(kw::meta) {
            input.parse::<kw::meta>()?;
            let content;
            braced!(content in input);

            let fields: Punctuated<_, Token![,]> = content.parse_terminated(ExprField::parse)?;
            Ok(TypeStatement::Meta(Vec::from_iter(fields.into_iter())))
        } else if lookahead.peek(kw::address) {
            input.parse::<kw::address>()?;
            // keep the grammar strict for now, we can loosen it to an expr later
            let content;
            parenthesized!(content in input);

            let offset: syn::LitInt = content.parse()?;
            let offset = offset.base10_parse()?;
            let fields = parse_optionally_braced_content(input, TypeField::parse)?;

            Ok(TypeStatement::Address(offset, fields))
        } else if lookahead.peek(kw::functions) {
            input.parse::<kw::functions>()?;

            let content;
            braced!(content in input);

            let function_blocks: Punctuated<(Ident, Vec<Function>), Token![,]> = content
                .parse_terminated(|input| {
                    let name: Ident = input.parse()?;

                    let content;
                    braced!(content in input);

                    let functions: Punctuated<_, Token![,]> =
                        content.parse_terminated(Function::parse)?;
                    let functions = Vec::from_iter(functions.into_iter());

                    Ok((name, functions))
                })?;
            let function_blocks = Vec::from_iter(function_blocks.into_iter());

            Ok(TypeStatement::Functions(function_blocks))
        } else if lookahead.peek(syn::Ident) {
            let ahead = input.fork();
            if let Ok(macro_call) = ahead.call(MacroCall::parse) {
                input.advance_to(&ahead);
                Ok(TypeStatement::Macro(macro_call))
            } else {
                Ok(TypeStatement::Field(input.parse()?))
            }
        } else {
            Err(lookahead.error())
        }
    }
}

impl Parse for TypeDefinition {
    fn parse(input: ParseStream) -> Result<Self> {
        input.parse::<Token![type]>()?;
        let name: Ident = input.parse()?;

        let statements = if input.peek(syn::Token![;]) {
            input.parse::<syn::Token![;]>()?;
            vec![]
        } else {
            let content;
            braced!(content in input);

            let statements: Punctuated<TypeStatement, Token![,]> =
                content.parse_terminated(TypeStatement::parse)?;
            Vec::from_iter(statements.into_iter())
        };

        Ok(TypeDefinition { name, statements })
    }
}

impl Parse for Module {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut uses = vec![];
        let mut extern_types = vec![];
        let mut extern_values = vec![];
        let mut definitions = vec![];

        // Exhaust all of our declarations
        while !input.is_empty() {
            if input.peek(syn::Token![use]) {
                input.parse::<syn::Token![use]>()?;
                let item_path = input.parse()?;
                input.parse::<syn::Token![;]>()?;
                uses.push(item_path);
            } else if input.peek(syn::Token![extern]) {
                input.parse::<syn::Token![extern]>()?;
                if input.peek(syn::Token![type]) {
                    input.parse::<syn::Token![type]>()?;
                    let ident: Ident = parse_type_ident(input)?.as_str().into();

                    let content;
                    braced!(content in input);

                    let fields: Punctuated<_, Token![,]> =
                        content.parse_terminated(ExprField::parse)?;

                    extern_types.push((ident, Vec::from_iter(fields.into_iter())));
                } else {
                    let name: Ident = input.parse()?;
                    input.parse::<syn::Token![:]>()?;
                    let type_: Type = input.parse()?;
                    input.parse::<syn::Token![@]>()?;
                    let address: Expr = input.parse()?;
                    input.parse::<syn::Token![;]>()?;

                    extern_values.push((
                        name,
                        type_,
                        address.int_literal().map(|i| i as usize).ok_or_else(|| {
                            input.error("expected integer for extern value address")
                        })?,
                    ));
                }
            } else if input.peek(syn::Token![type]) {
                definitions.push(input.parse()?);
            } else {
                return Err(input.error("unexpected keyword"));
            }
        }

        Ok(Module::new(
            &uses,
            &extern_types,
            &extern_values,
            &definitions,
        ))
    }
}

pub fn parse_str(input: &str) -> Result<Module> {
    syn::parse_str(input)
}
