#![allow(dead_code)]

use bitflags::bitflags;
use core::arch::asm;
use core::mem::MaybeUninit;


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Keyname {
    Einittoken = 0,
    Provision = 1,
    ProvisionSeal = 2,
    Report = 3,
    Seal = 4,
}

bitflags! {
    #[repr(C)]
    pub struct Keypolicy: u16 {
        const MRENCLAVE = 0b0000_0001;
        const MRSIGNER  = 0b0000_0010;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Enclu {
    EReport = 0,
    EGetkey = 1,
    EEnter = 2,
    EResume = 3,
    EExit = 4,
    EAccept = 5,
    EModpe = 6,
    EAcceptcopy = 7,
}

#[repr(align(16))]
pub struct Align16<T>(pub T);

#[repr(align(512))]
pub struct Align512<T>(pub T);

/// Call the `EGETKEY` instruction to obtain a 128-bit secret key.
pub fn egetkey(request: &Align512<[u8; 512]>) -> Result<Align16<[u8; 16]>, u32> {
    unsafe {
        let mut out = MaybeUninit::uninit();
        let error;

        asm!(
            // rbx is reserved by LLVM
            "xchg %rbx, {0}",
            "enclu",
            "mov {0}, %rbx",
            inout(reg) request => _,
            inlateout("eax") Enclu::EGetkey as u32 => error,
            in("rcx") out.as_mut_ptr(),
            options(att_syntax, nostack),
        );

        match error {
            0 => Ok(out.assume_init()),
            err => Err(err),
        }
    }
}

#[repr(C, align(512))]
pub struct Keyrequest {
    pub keyname: u16,
    pub keypolicy: Keypolicy,
    pub isvsvn: u16,
    pub _reserved1: u16,
    pub cpusvn: [u8; 16],
    pub attributemask: [u64; 2],
    pub keyid: [u8; 32],
    pub miscmask: u32,
    pub _reserved2: [u8; 436],
}

impl Keyrequest {
    fn copy(&self) -> [u8; 512] {
        unsafe { *(self as *const Keyrequest as *const [u8; 512]) }
    }

    pub fn egetkey(&self) -> Result<Align16<[u8; 16]>, u32> {
        egetkey(&Align512(self.copy()))
    }
}
