// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module defines [Session] and [Segment] which provides a way to share
//! execution traces between the execution phase and the proving phase.

use alloc::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{exec::SyscallRecord, MemoryImage};

/// Indicates how a [Segment] or [Session]'s execution has terminated
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum ExitCode {
    /// This indicates that the session limit has been reached.
    SessionLimit,

    /// This indicates normal termination of a program with an interior exit
    /// code returned from the guest.
    Halted(u32),
}

#[derive(Clone, Default, Serialize, Deserialize, Debug)]
pub struct PageFaults {
    pub(crate) reads: BTreeSet<u32>,
    pub(crate) writes: BTreeSet<u32>,
}

/// The execution trace of a program.
///
/// The record of memory transactions of an execution that starts from an
/// initial memory image (which includes the starting PC) and proceeds until
/// either a sys_halt or a sys_pause syscall is encountered. This record is
/// stored as a vector of [Segment]s.
#[derive(Serialize, Deserialize)]
pub struct Session {
    /// The constituent [Segment]s of the Session. The final [Segment] will have
    /// an [ExitCode] of [Halted](ExitCode::Halted), [Paused](ExitCode::Paused),
    /// or [SessionLimit](ExitCode::SessionLimit), and all other [Segment]s (if
    /// any) will have [ExitCode::SystemSplit].
    pub segments: Vec<Segment>,

    /// The data publicly committed by the guest program.
    // pub journal: Vec<u8>,

    /// The [ExitCode] of the session.
    pub exit_code: ExitCode,
}

/// The execution trace of a portion of a program.
///
/// The record of memory transactions of an execution that starts from an
/// initial memory image, and proceeds until terminated by the system or user.
/// This represents a chunk of execution work that will be proven in a single
/// call to the ZKP system. It does not necessarily represent an entire program;
/// see [Session] for tracking memory transactions until a user-requested
/// termination.
#[derive(Serialize, Deserialize)]
pub struct Segment {
    // pub(crate) pre_image: MemoryImage,
    // pub(crate) post_image_id: Digest,
    pub(crate) pc: u64,
    // pub(crate) faults: PageFaults,
    // pub(crate) syscalls: Vec<SyscallRecord>,
    pub(crate) exit_code: ExitCode,
    // The number of cycles in powers of 2.
    // pub po2: usize,
}

impl Session {
    /// Construct a new [Session] from its constituent components.
    pub fn new(segments: Vec<Segment>, exit_code: ExitCode) -> Self {
        Self {
            segments,
            // journal,
            exit_code,
        }
    }
}

impl Segment {
    /// Create a new [Segment] from its constituent components.
    pub(crate) fn new(
        pre_image: MemoryImage,
        // post_image_id: Digest,
        pc: u64,
        // faults: PageFaults,
        // syscalls: Vec<SyscallRecord>,
        exit_code: ExitCode,
        // po2: usize,
    ) -> Self {
        Self {
            // pre_image,
            // post_image_id,
            pc,
            // faults,
            // syscalls,
            exit_code,
            // po2,
        }
    }
}
