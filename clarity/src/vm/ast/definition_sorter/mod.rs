// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use hashbrown::{HashMap, HashSet};

use crate::vm::ast::errors::{ParseError, ParseErrors, ParseResult};
use crate::vm::ast::types::ContractAST;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{runtime_cost, CostTracker};
use crate::vm::functions::define::DefineFunctions;
use crate::vm::functions::NativeFunctions;
use crate::vm::representations::PreSymbolicExpressionType::{
    Atom, AtomValue, Comment, FieldIdentifier, List, Placeholder, SugaredContractIdentifier,
    SugaredFieldIdentifier, TraitReference, Tuple,
};
use crate::vm::representations::{ClarityName, PreSymbolicExpression};
use crate::vm::ClarityVersion;

#[cfg(test)]
mod tests;

pub struct DefinitionSorter {
    graph: Graph,
    top_level_expressions_map: HashMap<ClarityName, TopLevelExpressionIndex>,
}

impl DefinitionSorter {
    fn new() -> Self {
        Self {
            top_level_expressions_map: HashMap::new(),
            graph: Graph::new(),
        }
    }

    pub fn run_pass<T: CostTracker>(
        contract_ast: &mut ContractAST,
        accounting: &mut T,
        version: ClarityVersion,
    ) -> ParseResult<()> {
        let mut pass = DefinitionSorter::new();
        pass.run(contract_ast, accounting, version)?;
        Ok(())
    }

    pub fn run<T: CostTracker>(
        &mut self,
        contract_ast: &mut ContractAST,
        accounting: &mut T,
        version: ClarityVersion,
    ) -> ParseResult<()> {
        let exprs = contract_ast.pre_expressions[..].to_vec();
        for (expr_index, expr) in exprs.iter().enumerate() {
            self.graph.add_node(expr_index);

            if let Some((definition_name, atom_index, _)) = self.find_expression_definition(expr) {
                let tle = TopLevelExpressionIndex {
                    expr_index,
                    atom_index,
                };
                self.top_level_expressions_map.insert(definition_name, tle);
            }
        }

        for (expr_index, expr) in exprs.iter().enumerate() {
            self.probe_for_dependencies(expr, expr_index, version)?;
        }

        runtime_cost(
            ClarityCostFunction::AstCycleDetection,
            accounting,
            self.graph.edges_count()?,
        )?;

        let mut walker = GraphWalker::new();
        let sorted_indexes = walker.get_sorted_dependencies(&self.graph)?;

        if let Some(deps) = walker.get_cycling_dependencies(&self.graph, &sorted_indexes) {
            let functions_names = deps
                .into_iter()
                .filter_map(|i| {
                    let exp = &contract_ast.pre_expressions[i];
                    self.find_expression_definition(exp)
                })
                .map(|i| i.0.to_string())
                .collect::<Vec<_>>();

            let error = ParseError::new(ParseErrors::CircularReference(functions_names));
            return Err(error);
        }

        contract_ast.top_level_expression_sorting = Some(sorted_indexes);
        Ok(())
    }

    fn probe_for_dependencies(
        &mut self,
        expr: &PreSymbolicExpression,
        tle_index: usize,
        version: ClarityVersion,
    ) -> ParseResult<()> {
        match expr.pre_expr {
            Atom(ref name) => {
                if let Some(dep) = self.top_level_expressions_map.get(name) {
                    if dep.atom_index != expr.id {
                        self.graph.add_directed_edge(tle_index, dep.expr_index)?;
                    }
                }
                Ok(())
            }
            TraitReference(ref name) => {
                if let Some(dep) = self.top_level_expressions_map.get(name) {
                    if dep.atom_index != expr.id {
                        self.graph.add_directed_edge(tle_index, dep.expr_index)?;
                    }
                }
                Ok(())
            }
            List(ref exprs) => {
                // Filter comments out of the list of expressions.
                let filtered_exprs: Vec<&PreSymbolicExpression> = exprs
                    .iter()
                    .filter(|expr| expr.match_comment().is_none())
                    .collect();

                // Avoid looking for dependencies in tuples
                // TODO: Eliminate special handling of tuples as it is a separate presymbolic expression type
                if let Some((function_name, rest)) = filtered_exprs.split_first() {
                    let function_args = rest.to_vec();
                    if let Some(function_name) = function_name.match_atom() {
                        if let Some(define_function) =
                            DefineFunctions::lookup_by_name(function_name)
                        {
                            match define_function {
                                DefineFunctions::PersistedVariable | DefineFunctions::Constant => {
                                    // Args: [(define-name-and-types), ...]: ignore 1st arg
                                    if !function_args.is_empty() {
                                        for expr in function_args[1..function_args.len()].iter() {
                                            self.probe_for_dependencies(expr, tle_index, version)?;
                                        }
                                    }
                                    return Ok(());
                                }
                                DefineFunctions::PublicFunction
                                | DefineFunctions::PrivateFunction
                                | DefineFunctions::ReadOnlyFunction => {
                                    // Args: [(define-name-and-types), ...]
                                    if function_args.len() == 2 {
                                        self.probe_for_dependencies_in_define_args(
                                            function_args[0],
                                            tle_index,
                                            version,
                                        )?;
                                        self.probe_for_dependencies(
                                            function_args[1],
                                            tle_index,
                                            version,
                                        )?;
                                    }
                                    return Ok(());
                                }
                                DefineFunctions::Map => {
                                    // Args: [name, key, value]: with key value being potentially tuples
                                    if function_args.len() == 3 {
                                        self.probe_for_dependencies(
                                            function_args[1],
                                            tle_index,
                                            version,
                                        )?;
                                        self.probe_for_dependencies(
                                            function_args[2],
                                            tle_index,
                                            version,
                                        )?;
                                    }
                                    return Ok(());
                                }
                                DefineFunctions::Trait => {
                                    if function_args.len() != 2 {
                                        return Ok(());
                                    }
                                    if let Some(trait_sig) = function_args[1].match_list() {
                                        for func_sig in trait_sig.iter() {
                                            if let Some(func_sig) = func_sig.match_list() {
                                                if func_sig.len() == 3 {
                                                    self.probe_for_dependencies(
                                                        &func_sig[1],
                                                        tle_index,
                                                        version,
                                                    )?;
                                                    self.probe_for_dependencies(
                                                        &func_sig[2],
                                                        tle_index,
                                                        version,
                                                    )?;
                                                }
                                            }
                                        }
                                    }
                                    return Ok(());
                                }
                                DefineFunctions::ImplTrait | DefineFunctions::UseTrait => {
                                    return Ok(())
                                }
                                DefineFunctions::NonFungibleToken => return Ok(()),
                                DefineFunctions::FungibleToken => {
                                    // probe_for_dependencies if the supply arg (optional) is being passed
                                    if function_args.len() == 2 {
                                        self.probe_for_dependencies(
                                            function_args[1],
                                            tle_index,
                                            version,
                                        )?;
                                    }
                                    return Ok(());
                                }
                            }
                        } else if let Some(native_function) =
                            NativeFunctions::lookup_by_name_at_version(function_name, &version)
                        {
                            match native_function {
                                NativeFunctions::ContractCall => {
                                    // Args: [contract-name, function-name, ...]: ignore contract-name, function-name, handle rest
                                    if function_args.len() > 2 {
                                        for expr in function_args[2..].iter() {
                                            self.probe_for_dependencies(expr, tle_index, version)?;
                                        }
                                    }
                                    return Ok(());
                                }
                                NativeFunctions::Let => {
                                    // Args: [((name-1 value-1) (name-2 value-2)), ...]: handle 1st arg as a tuple
                                    if function_args.len() > 1 {
                                        if let Some(bindings) = function_args[0].match_list() {
                                            self.probe_for_dependencies_in_list_of_wrapped_key_value_pairs(bindings.iter().collect(), tle_index, version)?;
                                        }
                                        for expr in function_args[1..function_args.len()].iter() {
                                            self.probe_for_dependencies(expr, tle_index, version)?;
                                        }
                                    }
                                    return Ok(());
                                }
                                NativeFunctions::TupleGet => {
                                    // Args: [key-name, expr]: ignore key-name
                                    if function_args.len() == 2 {
                                        self.probe_for_dependencies(
                                            function_args[1],
                                            tle_index,
                                            version,
                                        )?;
                                    }
                                    return Ok(());
                                }
                                NativeFunctions::TupleCons => {
                                    // Args: [(key-name A), (key-name-2 B), ...]: handle as a tuple
                                    self.probe_for_dependencies_in_list_of_wrapped_key_value_pairs(
                                        function_args,
                                        tle_index,
                                        version,
                                    )?;
                                    return Ok(());
                                }
                                _ => {}
                            }
                        }
                    }
                }
                for expr in filtered_exprs.into_iter() {
                    self.probe_for_dependencies(expr, tle_index, version)?;
                }
                Ok(())
            }
            Tuple(ref exprs) => {
                self.probe_for_dependencies_in_tuple(exprs, tle_index, version)?;
                Ok(())
            }
            AtomValue(_)
            | FieldIdentifier(_)
            | SugaredContractIdentifier(_)
            | SugaredFieldIdentifier(_, _)
            | Comment(_)
            | Placeholder(_) => Ok(()),
        }
    }

    /// accept a slice of expected-pairs, e.g., [ (a b) (c d) (e f) ], and
    ///   probe them for dependencies as if they were part of a tuple definition.
    fn probe_for_dependencies_in_tuple(
        &mut self,
        pairs: &[PreSymbolicExpression],
        tle_index: usize,
        version: ClarityVersion,
    ) -> ParseResult<()> {
        let pairs = pairs
            .chunks(2)
            .map(|pair| pair.to_vec().into_boxed_slice())
            .collect::<Vec<_>>();

        for pair in pairs.iter() {
            self.probe_for_dependencies_in_key_value_pair(pair, tle_index, version)?;
        }
        Ok(())
    }

    fn probe_for_dependencies_in_define_args(
        &mut self,
        expr: &PreSymbolicExpression,
        tle_index: usize,
        version: ClarityVersion,
    ) -> ParseResult<()> {
        if let Some(func_sig) = expr.match_list() {
            // Func definitions can look like:
            // 1. (define-public func_name body)
            // 2. (define-public (func_name (arg uint) ...) body)
            // The goal here is to traverse case 2, looking for trait references
            if let Some((_, pairs)) = func_sig.split_first() {
                let pairs_vec: Vec<&PreSymbolicExpression> = pairs.iter().collect();
                self.probe_for_dependencies_in_list_of_wrapped_key_value_pairs(
                    pairs_vec, tle_index, version,
                )?;
            }
        }
        Ok(())
    }

    fn probe_for_dependencies_in_list_of_wrapped_key_value_pairs(
        &mut self,
        pairs: Vec<&PreSymbolicExpression>,
        tle_index: usize,
        version: ClarityVersion,
    ) -> ParseResult<()> {
        for pair in pairs.iter() {
            self.probe_for_dependencies_in_wrapped_key_value_pairs(pair, tle_index, version)?;
        }
        Ok(())
    }

    fn probe_for_dependencies_in_wrapped_key_value_pairs(
        &mut self,
        expr: &PreSymbolicExpression,
        tle_index: usize,
        version: ClarityVersion,
    ) -> ParseResult<()> {
        if let Some(pair) = expr.match_list() {
            self.probe_for_dependencies_in_key_value_pair(pair, tle_index, version)?;
        }
        Ok(())
    }

    fn probe_for_dependencies_in_key_value_pair(
        &mut self,
        pair: &[PreSymbolicExpression],
        tle_index: usize,
        version: ClarityVersion,
    ) -> ParseResult<()> {
        if pair.len() == 2 {
            self.probe_for_dependencies(&pair[1], tle_index, version)?;
        }
        Ok(())
    }

    fn find_expression_definition<'b>(
        &mut self,
        exp: &'b PreSymbolicExpression,
    ) -> Option<(ClarityName, u64, &'b PreSymbolicExpression)> {
        let args = {
            let exp = exp.match_list()?;
            let (function_name, args) = exp.split_first()?;
            let function_name = function_name.match_atom()?;
            DefineFunctions::lookup_by_name(function_name)?;
            Some(args)
        }?;
        let defined_name = match args.first()?.match_list() {
            Some(list) => list.first()?,
            _ => &args[0],
        };
        let tle_name = defined_name.match_atom()?;
        Some((tle_name.clone(), defined_name.id, defined_name))
    }
}

pub struct TopLevelExpressionIndex {
    expr_index: usize,
    atom_index: u64,
}

struct Graph {
    adjacency_list: Vec<Vec<usize>>,
}

impl Graph {
    fn new() -> Self {
        Self {
            adjacency_list: Vec::new(),
        }
    }

    fn add_node(&mut self, _expr_index: usize) {
        self.adjacency_list.push(vec![]);
    }

    fn add_directed_edge(
        &mut self,
        src_expr_index: usize,
        dst_expr_index: usize,
    ) -> ParseResult<()> {
        let list = self
            .adjacency_list
            .get_mut(src_expr_index)
            .ok_or(ParseErrors::InterpreterFailure)?;
        list.push(dst_expr_index);
        Ok(())
    }

    fn get_node_descendants(&self, expr_index: usize) -> Vec<usize> {
        self.adjacency_list[expr_index].clone()
    }

    fn has_node_descendants(&self, expr_index: usize) -> bool {
        !self.adjacency_list[expr_index].is_empty()
    }

    fn nodes_count(&self) -> usize {
        self.adjacency_list.len()
    }

    fn edges_count(&self) -> ParseResult<u64> {
        let mut total: u64 = 0;
        for node in self.adjacency_list.iter() {
            total = total
                .checked_add(node.len() as u64)
                .ok_or(ParseErrors::CostOverflow)?;
        }
        Ok(total)
    }
}

struct GraphWalker {
    seen: HashSet<usize>,
}

impl GraphWalker {
    fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    /// Depth-first search producing a post-order sort
    fn get_sorted_dependencies(&mut self, graph: &Graph) -> ParseResult<Vec<usize>> {
        let mut sorted_indexes = Vec::<usize>::new();
        for expr_index in 0..graph.nodes_count() {
            self.sort_dependencies_recursion(expr_index, graph, &mut sorted_indexes);
        }

        Ok(sorted_indexes)
    }

    fn sort_dependencies_recursion(
        &mut self,
        tle_index: usize,
        graph: &Graph,
        branch: &mut Vec<usize>,
    ) {
        if self.seen.contains(&tle_index) {
            return;
        }

        self.seen.insert(tle_index);
        if let Some(list) = graph.adjacency_list.get(tle_index) {
            for neighbor in list.iter() {
                self.sort_dependencies_recursion(*neighbor, graph, branch);
            }
        }
        branch.push(tle_index);
    }

    fn get_cycling_dependencies(
        &mut self,
        graph: &Graph,
        sorted_indexes: &[usize],
    ) -> Option<Vec<usize>> {
        let mut tainted: HashSet<usize> = HashSet::new();

        for node in sorted_indexes.iter() {
            let mut tainted_descendants_count = 0;
            let descendants = graph.get_node_descendants(*node);
            for descendant in descendants.iter() {
                if !graph.has_node_descendants(*descendant) || tainted.contains(descendant) {
                    tainted.insert(*descendant);
                    tainted_descendants_count += 1;
                }
            }
            if tainted_descendants_count == descendants.len() {
                tainted.insert(*node);
            }
        }

        if tainted.len() == sorted_indexes.len() {
            return None;
        }

        let nodes = HashSet::from_iter(sorted_indexes.iter().cloned());
        let deps = nodes.difference(&tainted).copied().collect();
        Some(deps)
    }
}
