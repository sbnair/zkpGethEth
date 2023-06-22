// Copyright 2021 Gregory Chadwick <mail@gregchadwick.co.uk>
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::instruction_formats;
use super::InstructionProcessor;

fn process_opcode_op<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let dec_insn = instruction_formats::RType::new(insn_bits);

    match dec_insn.funct3 {
        0b000 => match dec_insn.funct7 {
            0b000_0000 => Some(processor.process_add(dec_insn)),
            0b000_0001 => Some(processor.process_mul(dec_insn)),
            0b010_0000 => Some(processor.process_sub(dec_insn)),
            _ => None,
        },
        0b001 => match dec_insn.funct7 {
            0b000_0000 => Some(processor.process_sll(dec_insn)),
            0b000_0001 => Some(processor.process_mulh(dec_insn)),
            _ => None,
        },
        0b010 => match dec_insn.funct7 {
            0b000_0000 => Some(processor.process_slt(dec_insn)),
            0b000_0001 => Some(processor.process_mulhsu(dec_insn)),
            _ => None,
        },
        0b011 => match dec_insn.funct7 {
            0b000_0000 => Some(processor.process_sltu(dec_insn)),
            0b000_0001 => Some(processor.process_mulhu(dec_insn)),
            _ => None,
        },
        0b100 => match dec_insn.funct7 {
            0b000_0000 => Some(processor.process_xor(dec_insn)),
            0b000_0001 => Some(processor.process_div(dec_insn)),
            _ => None,
        },
        0b101 => match dec_insn.funct7 {
            0b000_0000 => Some(processor.process_srl(dec_insn)),
            0b000_0001 => Some(processor.process_divu(dec_insn)),
            0b010_0000 => Some(processor.process_sra(dec_insn)),
            _ => None,
        },
        0b110 => match dec_insn.funct7 {
            0b000_0000 => Some(processor.process_or(dec_insn)),
            0b000_0001 => Some(processor.process_rem(dec_insn)),
            _ => None,
        },
        0b111 => match dec_insn.funct7 {
            0b000_0000 => Some(processor.process_and(dec_insn)),
            0b000_0001 => Some(processor.process_remu(dec_insn)),
            _ => None,
        },
        _ => None,
    }
}

fn process_opcode_fence<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let dec_insn = instruction_formats::IType::new(insn_bits);
    Some(processor.process_fence(dec_insn))
}

fn process_opcode_opw<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let dec_insn = instruction_formats::RType::new(insn_bits);

    match dec_insn.funct3 {
        0b000 => match dec_insn.funct7 {
            0b000_0001 => Some(processor.process_mulw(dec_insn)),
            _ => None,
        },
        // 0b001 => match dec_insn.funct7 {
        //     0b000_0000 => Some(processor.process_sll(dec_insn)),
        //     0b000_0001 => Some(processor.process_mulh(dec_insn)),
        //     _ => None,
        // },
        // 0b010 => match dec_insn.funct7 {
        //     0b000_0000 => Some(processor.process_slt(dec_insn)),
        //     0b000_0001 => Some(processor.process_mulhsu(dec_insn)),
        //     _ => None,
        // },
        // 0b011 => match dec_insn.funct7 {
        //     0b000_0000 => Some(processor.process_sltu(dec_insn)),
        //     0b000_0001 => Some(processor.process_mulhu(dec_insn)),
        //     _ => None,
        // },
        // 0b100 => match dec_insn.funct7 {
        //     0b000_0000 => Some(processor.process_xor(dec_insn)),
        //     0b000_0001 => Some(processor.process_div(dec_insn)),
        //     _ => None,
        // },
        // 0b101 => match dec_insn.funct7 {
        //     0b000_0000 => Some(processor.process_srl(dec_insn)),
        //     0b000_0001 => Some(processor.process_divu(dec_insn)),
        //     0b010_0000 => Some(processor.process_sra(dec_insn)),
        //     _ => None,
        // },
        // 0b110 => match dec_insn.funct7 {
        //     0b000_0000 => Some(processor.process_or(dec_insn)),
        //     0b000_0001 => Some(processor.process_rem(dec_insn)),
        //     _ => None,
        // },
        0b111 => match dec_insn.funct7 {
            0b000_0001 => Some(processor.process_remuw(dec_insn)),
            _ => None,
        },
        _ => None,
    }
}

fn process_opcode_system<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let dec_insn = instruction_formats::CType::new(insn_bits);

    match dec_insn.funct3 {
        0b010 => Some(processor.process_rdtime(dec_insn)),
        _ => None,
    }
}

fn process_opcode_amo<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let dec_insn = instruction_formats::AType::new(insn_bits);

    match (dec_insn.funct3, dec_insn.funct5) {
        (0b010, 0b00001) => Some(processor.process_amoswapw(dec_insn)),
        (0b011, 0b00000) => Some(processor.process_amoaddd(dec_insn)),
        (0b011, 0b00001) => Some(processor.process_amoswapd(dec_insn)),
        (0b011, 0b00010) => Some(processor.process_amolrd(dec_insn)),
        (0b011, 0b00011) => Some(processor.process_amoscd(dec_insn)),
        (0b010, 0b00010) => Some(processor.process_amolrw(dec_insn)),
        (0b010, 0b00011) => Some(processor.process_amoscw(dec_insn)),
        (0b010, 0b01000) => Some(processor.process_amoorw(dec_insn)),
        (0b010, 0b01100) => Some(processor.process_amoandw(dec_insn)),
        (0b010, 0b00000) => Some(processor.process_amoaddw(dec_insn)),
        _ => None,
    }
}

fn process_opcode_op_imm<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let dec_insn = instruction_formats::IType::new(insn_bits);

    match dec_insn.funct3 {
        0b000 => Some(processor.process_addi(dec_insn)),
        0b001 => Some(processor.process_slli(instruction_formats::ITypeRV64Shamt::new(insn_bits))),
        0b010 => Some(processor.process_slti(dec_insn)),
        0b011 => Some(processor.process_sltui(dec_insn)),
        0b100 => Some(processor.process_xori(dec_insn)),
        0b101 => {
            let dec_insn_shamt = instruction_formats::ITypeRV64Shamt::new(insn_bits);
            match dec_insn_shamt.funct7 {
                0b000_000 => Some(processor.process_srli(dec_insn_shamt)),
                0b010_000 => Some(processor.process_srai(dec_insn_shamt)),
                _ => None,
            }
        }
        0b110 => Some(processor.process_ori(dec_insn)),
        0b111 => Some(processor.process_andi(dec_insn)),
        _ => None,
    }
}

fn process_opcode_branch<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let dec_insn = instruction_formats::BType::new(insn_bits);

    match dec_insn.funct3 {
        0b000 => Some(processor.process_beq(dec_insn)),
        0b001 => Some(processor.process_bne(dec_insn)),
        0b100 => Some(processor.process_blt(dec_insn)),
        0b101 => Some(processor.process_bge(dec_insn)),
        0b110 => Some(processor.process_bltu(dec_insn)),
        0b111 => Some(processor.process_bgeu(dec_insn)),
        _ => None,
    }
}

fn process_opcode_load<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let dec_insn = instruction_formats::IType::new(insn_bits);

    match dec_insn.funct3 {
        0b000 => Some(processor.process_lb(dec_insn)),
        0b001 => Some(processor.process_lh(dec_insn)),
        0b010 => Some(processor.process_lw(dec_insn)),
        0b011 => Some(processor.process_ld(dec_insn)),
        0b100 => Some(processor.process_lbu(dec_insn)),
        0b101 => Some(processor.process_lhu(dec_insn)),
        0b110 => Some(processor.process_lwu(dec_insn)),
        _ => None,
    }
}

fn process_opcode_store<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let dec_insn = instruction_formats::SType::new(insn_bits);
    // println!(" process_opcode_store with dec_insn {:?}", dec_insn);

    match dec_insn.funct3 {
        0b000 => Some(processor.process_sb(dec_insn)),
        0b001 => Some(processor.process_sh(dec_insn)),
        0b010 => Some(processor.process_sw(dec_insn)),
        0b011 => Some(processor.process_sd(dec_insn)),
        _ => None,
    }
}

/// Decodes instruction in `insn_bits` calling the appropriate function in `processor` returning
/// the result it produces.
///
/// Returns `None` if instruction doesn't decode into a valid instruction.
pub fn process_instruction<T: InstructionProcessor>(
    processor: &mut T,
    insn_bits: u32,
) -> Option<T::InstructionResult> {
    let opcode: u32 = insn_bits & 0x7f;

    match opcode {
        instruction_formats::OPCODE_OP => process_opcode_op(processor, insn_bits),
        instruction_formats::OPCODE_OPW => process_opcode_opw(processor, insn_bits),
        instruction_formats::OPCODE_SYSTEM => process_opcode_system(processor, insn_bits),
        instruction_formats::OPCODE_AMO => process_opcode_amo(processor, insn_bits),
        instruction_formats::OPCODE_OP_IMM => process_opcode_op_imm(processor, insn_bits),
        instruction_formats::OPCODE_LUI => {
            Some(processor.process_lui(instruction_formats::UType::new(insn_bits)))
        }
        instruction_formats::OPCODE_AUIPC => {
            Some(processor.process_auipc(instruction_formats::UType::new(insn_bits)))
        }
        instruction_formats::OPCODE_IW => {
            let dec_insn = instruction_formats::IType::new(insn_bits);
            match dec_insn.funct3 {
                0b000 => Some(processor.process_addiw(dec_insn)),
                _ => None,
            }
        }
        instruction_formats::OPCODE_BRANCH => process_opcode_branch(processor, insn_bits),
        instruction_formats::OPCODE_LOAD => process_opcode_load(processor, insn_bits),
        instruction_formats::OPCODE_STORE => process_opcode_store(processor, insn_bits),
        instruction_formats::OPCODE_JAL => {
            Some(processor.process_jal(instruction_formats::JType::new(insn_bits)))
        }
        instruction_formats::OPCODE_JALR => {
            Some(processor.process_jalr(instruction_formats::IType::new(insn_bits)))
        }
        instruction_formats::OPCODE_MISC_MEM => {
            let dec_insn = instruction_formats::IType::new(insn_bits);
            match dec_insn.funct3 {
                0b000 => Some(processor.process_fence(dec_insn)),
                _ => None,
            }
        }
        _ => None,
    }
}
