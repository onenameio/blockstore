// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
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

pub mod contexts;
pub mod v2_05;
pub mod v2_1;

use stacks_common::types::StacksEpochId;

use super::errors::{CheckErrors, CheckResult};
pub use super::types::{AnalysisPass, ContractAnalysis};
use super::AnalysisDatabase;
use crate::vm::costs::CostTracker;
use crate::vm::types::{FunctionType, TypeSignature};
use crate::vm::{ClarityVersion, Value};

impl FunctionType {
    pub fn check_args<T: CostTracker>(
        &self,
        accounting: &mut T,
        args: &[TypeSignature],
        epoch: StacksEpochId,
        clarity_version: ClarityVersion,
    ) -> CheckResult<TypeSignature> {
        match epoch {
            StacksEpochId::Epoch20 | StacksEpochId::Epoch2_05 => {
                self.check_args_2_05(accounting, args)
            }
            StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31 => self.check_args_2_1(accounting, args, clarity_version),
            StacksEpochId::Epoch10 => {
                Err(CheckErrors::Expects("Epoch10 is not supported".into()).into())
            }
        }
    }

    pub fn check_args_by_allowing_trait_cast(
        &self,
        db: &mut AnalysisDatabase,
        func_args: &[Value],
        epoch: StacksEpochId,
        clarity_version: ClarityVersion,
    ) -> CheckResult<TypeSignature> {
        match epoch {
            StacksEpochId::Epoch20 | StacksEpochId::Epoch2_05 => {
                self.check_args_by_allowing_trait_cast_2_05(db, func_args)
            }
            StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31 => {
                self.check_args_by_allowing_trait_cast_2_1(db, clarity_version, func_args)
            }
            StacksEpochId::Epoch10 => {
                Err(CheckErrors::Expects("Epoch10 is not supported".into()).into())
            }
        }
    }
}

fn is_reserved_word_v3(word: &str) -> bool {
    word == "block-height"
}

/// Is this a reserved word that should trigger an analysis error for the given
/// Clarity version? Note that most of the reserved words do not trigger an
/// analysis error, but will trigger an error at runtime. This should likely be
/// changed in a future Clarity version.
pub fn is_reserved_word(word: &str, version: ClarityVersion) -> bool {
    match version {
        ClarityVersion::Clarity1 | ClarityVersion::Clarity2 => false,
        ClarityVersion::Clarity3 => is_reserved_word_v3(word),
    }
}
