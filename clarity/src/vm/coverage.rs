use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;

use hashbrown::{HashMap, HashSet};

use super::functions::define::DefineFunctionsParsed;
use super::EvalHook;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::SymbolicExpression;

pub struct CoverageReporter {
    executed_lines: HashMap<QualifiedContractIdentifier, HashMap<u32, u64>>,
}

#[derive(Serialize, Deserialize)]
struct ContractFileInfo {
    contract: String,
    src_file: String,
    executable_lines: Vec<u32>,
}

#[derive(Serialize, Deserialize)]
struct CoverageFileInfo {
    coverage: HashMap<String, Vec<(u32, u64)>>,
}

impl Default for CoverageReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageReporter {
    pub fn new() -> CoverageReporter {
        CoverageReporter {
            executed_lines: HashMap::new(),
        }
    }

    #[cfg(not(feature = "developer-mode"))]
    pub fn report_eval(
        &mut self,
        _expr: &SymbolicExpression,
        _contract: &QualifiedContractIdentifier,
    ) {
    }

    #[cfg(feature = "developer-mode")]
    pub fn report_eval(
        &mut self,
        expr: &SymbolicExpression,
        contract: &QualifiedContractIdentifier,
    ) {
        if expr.match_list().is_some() {
            // don't count the whole list expression: wait until we've eval'ed the
            //   list components
            return;
        }

        // other sexps can only span 1 line
        let line_executed = expr.span.start_line;

        if let Some(execution_map_contract) = self.executed_lines.get_mut(contract) {
            if let Some(execution_count) = execution_map_contract.get_mut(&line_executed) {
                *execution_count += 1;
            } else {
                execution_map_contract.insert(line_executed, 1);
            }
        } else {
            let mut execution_map_contract = HashMap::new();
            execution_map_contract.insert(line_executed, 1);
            self.executed_lines
                .insert(contract.clone(), execution_map_contract);
        }
    }

    pub fn to_file<P: AsRef<std::path::Path> + Copy>(&self, filename: P) -> std::io::Result<()> {
        let f = File::create(filename)?;
        let iter = self.executed_lines.iter();
        let mut coverage = HashMap::with_capacity(iter.len());
        for (contract, execution_map) in iter {
            let mut executed_lines = execution_map
                .iter()
                .map(|(line, count)| (*line, *count))
                .collect::<Vec<_>>();

            executed_lines.sort_by_key(|f| f.0);

            coverage.insert(contract.to_string(), executed_lines);
        }

        let out = CoverageFileInfo { coverage };
        if let Err(e) = serde_json::to_writer(f, &out) {
            error!(
                "Failed to serialize JSON to coverage file {}: {}",
                filename.as_ref().display(),
                e
            );
            return Err(e.into());
        }

        Ok(())
    }

    fn executable_lines(exprs: &[SymbolicExpression]) -> Vec<u32> {
        let mut lines = vec![];
        let mut lines_seen = HashSet::new();
        for expression in exprs.iter() {
            let mut frontier = vec![expression];
            while let Some(cur_expr) = frontier.pop() {
                // handle defines: the `define-` atom is non executable, and neither are any of the type arguments,
                //  but the bodies of functions, the value of a constant, initial values for variables, and the
                //  max supply of FTs
                if let Some(define_expr) = DefineFunctionsParsed::try_parse(cur_expr).ok().flatten()
                {
                    match define_expr {
                        DefineFunctionsParsed::Constant { name: _, value } => {
                            frontier.push(value);
                        }
                        DefineFunctionsParsed::PrivateFunction { signature: _, body }
                        | DefineFunctionsParsed::PublicFunction { signature: _, body }
                        | DefineFunctionsParsed::ReadOnlyFunction { signature: _, body } => {
                            frontier.push(body);
                        }
                        DefineFunctionsParsed::BoundedFungibleToken {
                            name: _,
                            max_supply,
                        } => {
                            frontier.push(max_supply);
                        }
                        DefineFunctionsParsed::PersistedVariable {
                            name: _,
                            data_type: _,
                            initial,
                        } => {
                            frontier.push(initial);
                        }
                        DefineFunctionsParsed::NonFungibleToken { .. } => {}
                        DefineFunctionsParsed::UnboundedFungibleToken { .. } => {}
                        DefineFunctionsParsed::Map { .. } => {}
                        DefineFunctionsParsed::Trait { .. } => {}
                        DefineFunctionsParsed::UseTrait { .. } => {}
                        DefineFunctionsParsed::ImplTrait { .. } => {}
                    }

                    continue;
                }

                if let Some(children) = cur_expr.match_list() {
                    // don't count list expressions as a whole, just their children
                    frontier.extend(children);
                } else {
                    let line = cur_expr.span().start_line;
                    if !lines_seen.contains(&line) {
                        lines_seen.insert(line);
                        lines.push(line);
                    }
                }
            }
        }

        lines.sort();
        lines
    }

    pub fn register_src_file<P: AsRef<std::path::Path> + Copy>(
        contract: &QualifiedContractIdentifier,
        src_file_name: &str,
        ast: &[SymbolicExpression],
        filename: P,
    ) -> std::io::Result<()> {
        let f = File::create(filename)?;

        let executable_lines = CoverageReporter::executable_lines(ast);

        let json = ContractFileInfo {
            contract: contract.to_string(),
            src_file: src_file_name.to_string(),
            executable_lines,
        };

        if let Err(e) = serde_json::to_writer(f, &json) {
            error!(
                "Failed to serialize JSON to coverage file {}: {}",
                filename.as_ref().display(),
                e
            );
            return Err(e.into());
        }
        Ok(())
    }

    pub fn produce_lcov<P: AsRef<std::path::Path>>(
        out_filename: &str,
        register_files: &[P],
        coverage_files: &[P],
    ) -> std::io::Result<()> {
        let mut out = File::create(out_filename)?;

        for contract_filename in register_files.iter() {
            let reader = File::open(contract_filename)?;
            let info: ContractFileInfo = serde_json::from_reader(reader)?;
            let mut summed_coverage = BTreeMap::new();
            for coverage_filename in coverage_files.iter() {
                let cov_reader = File::open(coverage_filename)?;
                let coverage: CoverageFileInfo = serde_json::from_reader(cov_reader)?;
                if let Some(contract_coverage) = coverage.coverage.get(&info.contract) {
                    for (line, count) in contract_coverage.iter() {
                        if let Some(line_count) = summed_coverage.get_mut(line) {
                            *line_count += *count;
                        } else {
                            summed_coverage.insert(*line, *count);
                        }
                    }
                }
            }
            writeln!(out, "TN:{}", &info.contract)?;
            writeln!(out, "SF:{}", &info.src_file)?;
            for line in info.executable_lines.iter() {
                let count = summed_coverage.get(line).cloned().unwrap_or(0);
                writeln!(out, "DA:{},{}", line, count)?;
            }
            writeln!(out, "LH:{}", summed_coverage.len())?;
            writeln!(out, "LF:{}", &info.executable_lines.len())?;
            writeln!(out, "end_of_record")?;
        }

        Ok(())
    }
}

impl EvalHook for CoverageReporter {
    fn will_begin_eval(
        &mut self,
        env: &mut crate::vm::contexts::Environment,
        _context: &crate::vm::contexts::LocalContext,
        expr: &SymbolicExpression,
    ) {
        self.report_eval(expr, &env.contract_context.contract_identifier);
    }

    fn did_finish_eval(
        &mut self,
        _env: &mut crate::vm::Environment,
        _context: &crate::vm::LocalContext,
        _expr: &SymbolicExpression,
        _res: &core::result::Result<crate::vm::Value, crate::vm::errors::Error>,
    ) {
    }

    fn did_complete(
        &mut self,
        _result: core::result::Result<&mut crate::vm::ExecutionResult, String>,
    ) {
    }
}
