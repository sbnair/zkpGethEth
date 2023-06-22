// Copyright 2021 Gregory Chadwick <mail@gregchadwick.co.uk>
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! RISC-V instruction set simulator library
//!
//! Containts the building blocks for a RISC-V ISS. The seperate rrs-cli uses rrs-lib to implement
//! a CLI driven ISS.

pub mod instruction_executor;
pub mod instruction_formats;
pub mod instruction_string_outputter;
pub mod memories;
pub mod process_instruction;

use downcast_rs::{impl_downcast, Downcast};

pub use process_instruction::process_instruction;

/// A trait for objects which do something with RISC-V instructions (e.g. execute them or print a
/// disassembly string).
///
/// There is one function per RISC-V instruction. Each function takes the appropriate struct from
/// [instruction_formats] giving access to the decoded fields of the instruction. All functions
/// return the [InstructionProcessor::InstructionResult] associated type.
pub trait InstructionProcessor {
    type InstructionResult;

    fn process_add(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_sub(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_sll(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_slt(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_sltu(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_xor(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_srl(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_sra(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_or(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_amoorw(&mut self, dec_insn: instruction_formats::AType) -> Self::InstructionResult; // RV64
    fn process_amoandw(&mut self, dec_insn: instruction_formats::AType) -> Self::InstructionResult; // RV64
    fn process_and(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;

    fn process_addi(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_addiw(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_slli(
        &mut self,
        dec_insn: instruction_formats::ITypeRV64Shamt,
    ) -> Self::InstructionResult;
    fn process_slti(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_sltui(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_xori(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_srli(
        &mut self,
        dec_insn: instruction_formats::ITypeRV64Shamt,
    ) -> Self::InstructionResult;
    fn process_srai(
        &mut self,
        dec_insn: instruction_formats::ITypeRV64Shamt,
    ) -> Self::InstructionResult;
    fn process_ori(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_andi(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;

    fn process_lui(&mut self, dec_insn: instruction_formats::UType) -> Self::InstructionResult;
    fn process_auipc(&mut self, dec_insn: instruction_formats::UType) -> Self::InstructionResult;

    fn process_beq(&mut self, dec_insn: instruction_formats::BType) -> Self::InstructionResult;
    fn process_bne(&mut self, dec_insn: instruction_formats::BType) -> Self::InstructionResult;
    fn process_blt(&mut self, dec_insn: instruction_formats::BType) -> Self::InstructionResult;
    fn process_bltu(&mut self, dec_insn: instruction_formats::BType) -> Self::InstructionResult;
    fn process_bge(&mut self, dec_insn: instruction_formats::BType) -> Self::InstructionResult;
    fn process_bgeu(&mut self, dec_insn: instruction_formats::BType) -> Self::InstructionResult;

    fn process_lb(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_lbu(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_lh(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_ld(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult; // RV64I
    fn process_lhu(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_lw(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
    fn process_lwu(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult; // RV64I

    fn process_sb(&mut self, dec_insn: instruction_formats::SType) -> Self::InstructionResult;
    fn process_sh(&mut self, dec_insn: instruction_formats::SType) -> Self::InstructionResult;
    fn process_sw(&mut self, dec_insn: instruction_formats::SType) -> Self::InstructionResult;
    fn process_sd(&mut self, dec_insn: instruction_formats::SType) -> Self::InstructionResult; // RV64I

    fn process_amoswapw(&mut self, dec_insn: instruction_formats::AType)
        -> Self::InstructionResult;
    fn process_amoswapd(&mut self, dec_insn: instruction_formats::AType)
        -> Self::InstructionResult;
    fn process_amoaddd(&mut self, dec_insn: instruction_formats::AType) -> Self::InstructionResult;
    fn process_amolrd(&mut self, dec_insn: instruction_formats::AType) -> Self::InstructionResult;
    fn process_amoscd(&mut self, dec_insn: instruction_formats::AType) -> Self::InstructionResult;
    fn process_amolrw(&mut self, dec_insn: instruction_formats::AType) -> Self::InstructionResult;
    fn process_amoscw(&mut self, dec_insn: instruction_formats::AType) -> Self::InstructionResult;
    fn process_amoaddw(&mut self, dec_insn: instruction_formats::AType) -> Self::InstructionResult;

    fn process_rdtime(&mut self, dec_insn: instruction_formats::CType) -> Self::InstructionResult;

    fn process_jal(&mut self, dec_insn: instruction_formats::JType) -> Self::InstructionResult;
    fn process_jalr(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;

    fn process_mul(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_mulh(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_mulhu(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_mulhsu(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;

    fn process_mulw(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;

    fn process_div(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_divu(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_rem(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_remu(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult;
    fn process_remuw(&mut self, dec_insn: instruction_formats::RType) -> Self::InstructionResult; // RV64M

    fn process_fence(&mut self, dec_insn: instruction_formats::IType) -> Self::InstructionResult;
}

/// State of a single RISC-V hart (hardware thread)
pub struct HartState {
    /// x1 - x31 register values. The contents of index 0 (the x0 zero register) are ignored.
    pub registers: [u64; 32],
    /// Program counter
    pub pc: u64,
    /// Gives index of the last register written if one occurred in the previous instruciton. Set
    /// to `None` if latest instruction did not write a register.
    pub last_register_write: Option<usize>,
}

impl HartState {
    pub fn new() -> Self {
        HartState {
            registers: [0; 32],
            pc: 0,
            last_register_write: None,
        }
    }

    /// Write a register in the hart state. Used by executing instructions for correct zero
    /// register handling
    fn write_register(&mut self, reg_index: usize, data: u64) {
        if reg_index == 0 {
            return;
        }

        self.registers[reg_index] = data;
        self.last_register_write = Some(reg_index)
    }

    /// Read a register from the hart state. Used by executing instructions for correct zero
    /// register handling
    fn read_register(&self, reg_index: usize) -> u64 {
        if reg_index == 0 {
            0
        } else {
            self.registers[reg_index]
        }
    }
}

impl Default for HartState {
    fn default() -> Self {
        Self::new()
    }
}

/// The different sizes used for memory accesses
#[derive(Clone, Copy)]
pub enum MemAccessSize {
    /// 8 bits
    Byte,
    /// 16 bits
    HalfWord,
    /// 32 bits
    Word,
    /// 64 bits
    DoubleWord,
}

/// A trait for objects which implement memory operations
pub trait Memory: Downcast {
    /// Read `size` bytes from `addr`.
    ///
    /// `addr` must be aligned to `size`.
    /// Returns `None` if `addr` doesn't exist in this memory.
    fn read_mem(&mut self, addr: u64, size: MemAccessSize) -> Option<u64>;

    /// Write `size` bytes of `store_data` to `addr`
    ///
    /// `addr` must be aligned to `size`.
    /// Returns `true` if write succeeds.
    fn write_mem(&mut self, addr: u64, size: MemAccessSize, store_data: u64) -> bool;
}

impl_downcast!(Memory);

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use super::instruction_executor::{InstructionException, InstructionExecutor};
    use super::instruction_string_outputter::InstructionStringOutputter;
    use super::*;

    #[test]
    fn test_insn_execute() {
        let mut hart = HartState::new();
        let mut mem = memories::VecMemory::new(vec![
            0xbcd10113_1234b137,
            0x3aa18193_f387e1b7,
            0x7ac28293_bed892b7,
            0xf4e0e213_003100b3,
            0x00121463_02120a63,
            0x00c0036f_1542c093,
            0x402080b3_0020f0b3,
            0x02838393_00000397,
            0x00638483_0003a403,
            0x00139223_0023d503,
            0x00000000_0043a583,
            0x00000000_00000000,
            0xbaadf00d_deadbeef,
        ]);

        hart.pc = 0;

        // TODO: With the 'executor' concept we need to effectively create a new one each step as
        // it's meant to be just taking a reference to things to execute, but then if we want to
        // access those things we either do it via the executor or create a new one before the next
        // step to allow access via the 'main' object, could just make step part of the 'main'
        // object? Having the executor only coupled to a bare minimum of state could be good?
        let mut executor = InstructionExecutor {
            hart_state: &mut hart,
            mem: &mut mem,
        };

        while executor.hart_state.pc != 0x54 {
            let mut outputter = InstructionStringOutputter {
                insn_pc: executor.hart_state.pc,
            };
            let insn_bits = executor
                .mem
                .read_mem(executor.hart_state.pc, MemAccessSize::Word)
                .unwrap();

            let insn_bits = (insn_bits & 0xffffffff)
                .try_into()
                .expect("invalid instruction"); // only use lsb 32 bit address

            assert_eq!(executor.step(), Ok(()));

            println!(
                "{:x} {}",
                executor.hart_state.pc,
                process_instruction(&mut outputter, insn_bits).unwrap()
            );
            if let Some(reg_index) = executor.hart_state.last_register_write {
                println!(
                    "x{} = {:08x}",
                    reg_index, executor.hart_state.registers[reg_index]
                );
            }
        }

        assert_eq!(executor.hart_state.registers[1], 0x05bc8f77);
        assert_eq!(executor.hart_state.registers[2], 0x1234abcd);
        assert_eq!(executor.hart_state.registers[3], 0xfffffffff387e3aa);
        assert_eq!(executor.hart_state.registers[4], 0xffffffffffffff7f);
        assert_eq!(executor.hart_state.registers[5], 0xffffffffbed897ac);
        assert_eq!(executor.hart_state.registers[6], 0x00000030);
        assert_eq!(executor.hart_state.registers[7], 0x00000060);
        assert_eq!(executor.hart_state.registers[8], 0xdeadbeef);
        assert_eq!(executor.hart_state.registers[9], 0xffffffffffffffad);
        assert_eq!(executor.hart_state.registers[10], 0x0000dead);
        assert_eq!(executor.hart_state.registers[11], 0xbaad8f77);

        assert_eq!(
            executor.step(),
            Err(InstructionException::IllegalInstruction(0x54, 0))
        );
    }
}
