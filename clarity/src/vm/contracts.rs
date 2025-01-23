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

use stacks_common::types::StacksEpochId;

use crate::vm::ast::ContractAST;
use crate::vm::contexts::{ContractContext, GlobalContext};
use crate::vm::errors::InterpreterResult as Result;
use crate::vm::eval_all;
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::version::ClarityVersion;

#[derive(Serialize, Deserialize)]
pub struct Contract {
    pub contract_context: ContractContext,
}

// AARON: this is an increasingly useless wrapper around a ContractContext struct.
//          will probably be removed soon.
impl Contract {
    pub fn initialize_from_ast(
        contract_identifier: QualifiedContractIdentifier,
        contract: &ContractAST,
        sponsor: Option<PrincipalData>,
        global_context: &mut GlobalContext,
        version: ClarityVersion,
    ) -> Result<Contract> {
        let mut contract_context = ContractContext::new(contract_identifier, version);

        eval_all(
            &contract.expressions,
            &mut contract_context,
            global_context,
            sponsor,
        )?;

        Ok(Contract { contract_context })
    }

    pub fn canonicalize_types(&mut self, epoch: &StacksEpochId) {
        self.contract_context.canonicalize_types(epoch);
    }
}
