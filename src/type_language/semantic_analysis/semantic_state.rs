use std::{collections::HashMap, path::Path};

use crate::type_language::parser;

use super::{
    super::grammar::{self, ItemPath},
    module, type_registry, types,
};

use anyhow::Context;

pub struct SemanticState {
    pub(crate) modules: HashMap<ItemPath, module::Module>,
    pub(crate) type_registry: type_registry::TypeRegistry,
}

impl SemanticState {
    pub fn new(pointer_size: usize) -> Self {
        let mut semantic_state = Self {
            modules: HashMap::new(),
            type_registry: type_registry::TypeRegistry::new(pointer_size),
        };

        // Insert the empty root module.
        semantic_state.modules.insert(
            ItemPath::empty(),
            module::Module::new(ItemPath::empty(), grammar::Module::default(), vec![]),
        );

        // Insert all of our predefined types.
        let predefined_types = [
            ("void", 0),
            ("bool", 1),
            ("u8", 1),
            ("u16", 2),
            ("u32", 4),
            ("u64", 8),
            ("u128", 16),
            ("i8", 1),
            ("i16", 2),
            ("i32", 4),
            ("i64", 8),
            ("i128", 16),
            ("f32", 4),
            ("f64", 8),
        ];

        for (name, size) in predefined_types {
            let path = ItemPath::from_colon_delimited_str(name);
            semantic_state
                .add_type(types::TypeDefinition {
                    path: path,
                    state: types::TypeState::Resolved(types::TypeStateResolved::new(size)),
                    category: types::TypeCategory::Predefined,
                })
                .expect("failed to add predefined type");
        }

        semantic_state
    }

    // todo: define an actual error type
    pub fn add_file(&mut self, path: &Path) -> anyhow::Result<()> {
        self.add_module(
            &parser::parse_str(&std::fs::read_to_string(path)?).context(format!("{:?}", path))?,
            &ItemPath::from_path(path),
        )
    }

    pub fn add_module(&mut self, module: &grammar::Module, path: &ItemPath) -> anyhow::Result<()> {
        let extern_values: Vec<_> = module
            .extern_values
            .iter()
            .map(|(name, type_, address)| {
                (
                    name.as_str().to_owned(),
                    types::Type::Unresolved(grammar::TypeRef::Type(type_.clone())),
                    *address,
                )
            })
            .collect();

        self.modules.insert(
            path.clone(),
            module::Module::new(path.clone(), module.clone(), extern_values),
        );

        for definition in &module.definitions {
            let path = path.join(definition.name.as_str().into());
            self.add_type(types::TypeDefinition {
                path: path.clone(),
                state: types::TypeState::Unresolved(definition.clone()),
                category: types::TypeCategory::Defined,
            })?;
        }

        for (extern_path, fields) in &module.extern_types {
            let size = fields
                .iter()
                .find(|ef| ef.ident_as_str() == "size")
                .context("failed to find size field in extern type for module")?
                .1
                .int_literal()
                .context("size field of extern type is not an int literal")?
                .try_into()
                .context("the size could not be converted into an unsigned integer")?;

            let extern_path = path.join(extern_path.as_str().into());

            self.add_type(types::TypeDefinition {
                path: extern_path.clone(),
                state: types::TypeState::Resolved(types::TypeStateResolved::new(size)),
                category: types::TypeCategory::Extern,
            })?;
        }

        Ok(())
    }

    pub fn add_type(&mut self, type_definition: types::TypeDefinition) -> anyhow::Result<()> {
        let parent_path = &type_definition
            .path
            .parent()
            .context("failed to get parent type")?;
        self.modules
            .get_mut(parent_path)
            .context("failed to get module")?
            .definition_paths
            .insert(type_definition.path.clone());
        Ok(self.type_registry.add(type_definition))
    }

    pub fn build(mut self) -> anyhow::Result<ResolvedSemanticState> {
        loop {
            let to_resolve = self.type_registry.unresolved();
            if to_resolve.is_empty() {
                break;
            }

            for resolvee_path in &to_resolve {
                if let types::TypeState::Unresolved(definition) = self
                    .type_registry
                    .get(resolvee_path)
                    .context("failed to get type")?
                    .state
                    .clone()
                {
                    self.build_type(resolvee_path, &definition)?;
                }
            }

            if to_resolve == self.type_registry.unresolved() {
                // Oh no! We failed to resolve any new types!
                // Bail from the loop.
                return Err(anyhow::anyhow!(
                    "type resolution will not terminate, failed on types: {:?} (resolved types: {:?})",
                    Vec::from_iter(to_resolve.iter().map(|s| s.to_string())),
                    Vec::from_iter(self.type_registry.resolved().iter().map(|s| s.to_string())),
                ));
            }
        }

        // Now that we've finished resolving all of our types, we should be able
        // to resolve our extern values.
        for (_, module) in &mut self.modules {
            module.resolve_extern_values(&mut self.type_registry)?;
        }

        Ok(ResolvedSemanticState {
            modules: self.modules,
            type_registry: self.type_registry,
        })
    }
}

impl SemanticState {
    fn build_function(
        &self,
        scope: &[ItemPath],
        function: &grammar::Function,
    ) -> Result<types::Function, anyhow::Error> {
        let attributes = function
            .attributes
            .iter()
            .map(|a| match a {
                grammar::Attribute::Function(ident, exprs) => match (ident.as_str(), &exprs[..]) {
                    ("address", [grammar::Expr::IntLiteral(address)]) => {
                        Ok(types::Attribute::Address(*address as usize))
                    }
                    (_, _) => Err(anyhow::anyhow!(
                        "failed to resolve function attribute, unsupported name"
                    )),
                },
            })
            .collect::<Result<Vec<_>, _>>()?;

        let arguments = function
            .arguments
            .iter()
            .map(|a| match a {
                grammar::Argument::ConstSelf => Ok(types::Argument::ConstSelf),
                grammar::Argument::MutSelf => Ok(types::Argument::MutSelf),
                grammar::Argument::Field(grammar::TypeField(name, type_ref)) => {
                    Ok(types::Argument::Field(
                        name.0.clone(),
                        self.type_registry
                            .resolve_grammar_typeref(scope, type_ref)
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "failed to resolve type of field {:?} ({:?}",
                                    name,
                                    type_ref
                                )
                            })?,
                    ))
                }
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let return_type = function
            .return_type
            .as_ref()
            .and_then(|t| self.type_registry.resolve_grammar_type(scope, t));

        Ok(types::Function {
            name: function.name.0.clone(),
            attributes,
            arguments,
            return_type,
        })
    }

    fn build_type(
        &mut self,
        resolvee_path: &ItemPath,
        definition: &grammar::TypeDefinition,
    ) -> anyhow::Result<()> {
        let module = self
            .get_module_for_path(resolvee_path)
            .context("failed to get module for path")?;

        let build_region_from_field = |grammar::TypeField(ident, type_ref): &grammar::TypeField| {
            self.type_registry
                .resolve_grammar_typeref(&module.scope(), type_ref)
                .map(|tr| (None, types::Region::Field(ident.0.clone(), tr)))
        };

        let mut target_size: Option<usize> = None;
        let mut regions: Vec<(Option<usize>, types::Region)> = vec![];
        let mut metadata: HashMap<String, types::MetadataValue> = HashMap::new();
        let mut functions: HashMap<String, Vec<types::Function>> = HashMap::new();
        for statement in &definition.statements {
            match statement {
                grammar::TypeStatement::Meta(fields) => {
                    for field in fields {
                        if let grammar::ExprField(ident, grammar::Expr::IntLiteral(value)) = field {
                            if ident.0 == "size" {
                                target_size = Some(*value as usize);
                            } else if ident.0 == "singleton" {
                                metadata.insert(
                                    "singleton".to_string(),
                                    types::MetadataValue::Integer(*value as isize),
                                );
                            }
                        }
                    }
                }
                grammar::TypeStatement::Address(address, fields) => {
                    regions.push((Some(*address), types::Region::Padding(0)));
                    for type_field in fields {
                        if let Some(region_pair) = build_region_from_field(type_field) {
                            regions.push(region_pair);
                        } else {
                            return Ok(());
                        }
                    }
                }
                grammar::TypeStatement::Field(type_field) => {
                    if let Some(region_pair) = build_region_from_field(type_field) {
                        regions.push(region_pair);
                    } else {
                        return Ok(());
                    }
                }
                grammar::TypeStatement::Macro(macro_call) => match macro_call.match_repr() {
                    ("padding", [grammar::Expr::IntLiteral(size)]) => {
                        regions.push((None, types::Region::Padding(*size as usize)));
                    }
                    (name, _) => return Err(anyhow::anyhow!("unsupported macro: {}", name)),
                },
                grammar::TypeStatement::Functions(functions_by_category) => {
                    functions = functions_by_category
                        .iter()
                        .map(|(category, functions)| {
                            Ok((
                                category.0.clone(),
                                functions
                                    .iter()
                                    .map(|function| self.build_function(&module.scope(), function))
                                    .collect::<Result<Vec<_>, _>>()?,
                            ))
                        })
                        .collect::<anyhow::Result<HashMap<_, _>>>()?;
                }
            };
        }

        // this resolution algorithm is very simple and doesn't handle overlapping regions
        // or regions that are out of order
        let mut last_address: usize = 0;
        let mut resolved_regions = vec![];

        if let Some((type_definition, region, size)) =
            self.build_vftable(&resolvee_path, &functions)
        {
            self.add_type(type_definition)?;
            resolved_regions.push(region);
            last_address += size;
        }

        for (offset, region) in regions {
            if let Some(offset) = offset {
                let size = offset - last_address;
                resolved_regions.push(types::Region::Padding(size));
                last_address += size;
            }

            let region_size = match region.size(&self.type_registry) {
                Some(size) => size,
                None => return Ok(()),
            };

            if region_size == 0 {
                continue;
            }

            resolved_regions.push(region);
            last_address += region_size;
        }

        if let Some(target_size) = target_size {
            if last_address < target_size {
                resolved_regions.push(types::Region::Padding(target_size - last_address));
            }
        }

        let sizes = resolved_regions
            .iter()
            .map(|r: &types::Region| r.size(&self.type_registry))
            .collect::<Option<Vec<_>>>();

        if let Some(sizes) = sizes {
            let size = sizes.into_iter().sum();
            self.type_registry.get_mut(resolvee_path).unwrap().state =
                types::TypeState::Resolved(types::TypeStateResolved {
                    size,
                    regions: resolved_regions,
                    functions,
                    metadata,
                });
        }
        Ok(())
    }

    fn build_vftable(
        &self,
        resolvee_path: &ItemPath,
        functions: &HashMap<String, Vec<types::Function>>,
    ) -> Option<(types::TypeDefinition, types::Region, usize)> {
        let vftable = functions.get(&"vftable".to_string())?;
        let name = resolvee_path.last()?;

        let resolvee_vtable_path = resolvee_path
            .parent()?
            .join(format!("{}Vftable", name.as_str()).into());

        let function_to_field = |function: &types::Function| -> types::Region {
            let argument_to_type = |argument: &types::Argument| -> (String, Box<types::Type>) {
                match argument {
                    types::Argument::ConstSelf => (
                        "this".to_string(),
                        Box::new(types::Type::ConstPointer(Box::new(types::Type::Raw(
                            resolvee_path.clone(),
                        )))),
                    ),
                    types::Argument::MutSelf => (
                        "this".to_string(),
                        Box::new(types::Type::MutPointer(Box::new(types::Type::Raw(
                            resolvee_path.clone(),
                        )))),
                    ),
                    types::Argument::Field(name, type_ref) => {
                        (name.clone(), Box::new(type_ref.clone()))
                    }
                }
            };
            let arguments = function.arguments.iter().map(argument_to_type).collect();
            let return_type = function.return_type.as_ref().map(|t| Box::new(t.clone()));

            types::Region::Field(
                function.name.clone(),
                types::Type::Function(arguments, return_type),
            )
        };

        Some((
            types::TypeDefinition {
                path: resolvee_vtable_path.clone(),
                state: types::TypeState::Resolved(types::TypeStateResolved {
                    size: 0,
                    regions: vftable.iter().map(function_to_field).collect(),
                    functions: HashMap::new(),
                    metadata: HashMap::new(),
                }),
                category: types::TypeCategory::Defined,
            },
            types::Region::Field(
                "vftable".to_string(),
                types::Type::ConstPointer(Box::new(types::Type::Raw(resolvee_vtable_path))),
            ),
            self.type_registry.pointer_size(),
        ))
    }

    fn get_module_for_path(&self, path: &ItemPath) -> Option<&module::Module> {
        self.modules.get(&path.parent()?)
    }
}

pub struct ResolvedSemanticState {
    type_registry: type_registry::TypeRegistry,
    modules: HashMap<ItemPath, module::Module>,
}

impl ResolvedSemanticState {
    pub fn type_registry(&self) -> &type_registry::TypeRegistry {
        &self.type_registry
    }

    pub fn modules(&self) -> &HashMap<ItemPath, module::Module> {
        &self.modules
    }
}
