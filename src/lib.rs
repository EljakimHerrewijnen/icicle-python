use std::collections::HashMap;
use pyo3::prelude::*;
use icicle_vm;
use icicle_vm::linux::LinuxCpu;
use pyo3::exceptions::*;
use target_lexicon;
use sleigh_runtime::NamedRegister;
use unicorn_engine::{
    unicorn_const, 
    Permission as UCPERM,
    uc_error as UCERR
};

use std::{
    io::Write,
    os::raw::{c_int, c_void},
};

use icicle_vm::{
    cpu::{
        debug_info::{DebugInfo, SourceLocation},
        mem::perm,
        CpuSnapshot, ExceptionCode, HookHandler, ValueSource,
    },
    VmExit,
};

// References:
// - https://pyo3.rs/main/conversions/tables
// - https://pyo3.rs/main/class

pub fn uc_perms_to_icicle_perms(uc_perms: u32) -> u8 {
     let mut perm = perm::MAP;
    if uc_perms & UCPERM::EXEC != 0 {
        perm |= perm::EXEC;
    }
    if uc_perms & UCPERM::READ != 0 {
        perm |= perm::READ;
    }
    if uc_perms & UCPERM::WRITE != 0 {
        perm |= perm::WRITE;
    }
    perm
}

pub fn icicle_perms_to_uc_perms(perm: u8) -> u32 {
    let mut uc_perm = 0;
    if perm & perm::EXEC != 0 {
        uc_perm |= UCPERM::EXEC;
    }
    if perm & perm::READ != 0 {
        uc_perm |= UCPERM::READ;
    }
    if perm & perm::WRITE != 0 {
        uc_perm |= UCPERM::WRITE;
    }
    uc_perm
}

fn read_err_to_uc_err(err: icicle_vm::cpu::mem::MemError) -> uc_err {
    match err {
        icicle_vm::cpu::mem::MemError::Unmapped => UCERR::READ_UNMAPPED,
        icicle_vm::cpu::mem::MemError::ReadViolation => UCERR::READ_PROT,
        icicle_vm::cpu::mem::MemError::Unaligned => UCERR::READ_UNALIGNED,
        icicle_vm::cpu::mem::MemError::OutOfMemory => UCERR::NOMEM,
        _ => UCERR::EXCEPTION,
    }
}

#[allow(unused)]
fn write_err_to_uc_err(err: icicle_vm::cpu::mem::MemError) -> uc_err {
    match err {
        icicle_vm::cpu::mem::MemError::Unmapped => UCERR::WRITE_UNMAPPED,
        icicle_vm::cpu::mem::MemError::WriteViolation => UCERR::WRITE_PROT,
        icicle_vm::cpu::mem::MemError::Unaligned => UCERR::WRITE_UNALIGNED,
        icicle_vm::cpu::mem::MemError::OutOfMemory => UCERR::NOMEM,
        _ => UCERR::EXCEPTION,
    }
}

#[pyclass(unsendable, module = "icicle")]
struct IcicleUnicornAPI {
    vm: icicle_vm::Vm,
    regs: HashMap<String, NamedRegister>,
}

fn reg_find<'a>(i: &'a IcicleUnicornAPI, name: &str) -> PyResult<&'a NamedRegister> {
    let sleigh = i.vm.cpu.sleigh();
    match sleigh.get_reg(name) {
        None => {
            i.regs.get(name.to_lowercase().as_str())
                .ok_or(
                    PyKeyError::new_err(format!("Register not found: {name}"))
                )
        }
        Some(r) => Ok(r),
    }
}

#[pymethods]
impl IcicleUnicornAPI {
    #[getter]
    fn get_icount_limit(&mut self) -> u64 {
        self.vm.icount_limit
    }

    #[setter]
    fn set_icount_limit(&mut self, value: u64) {
        self.vm.icount_limit = value;
    }

    #[getter]
    fn get_icount(&mut self) -> u64 {
        return self.vm.cpu.icount;
    }

    #[setter]
    fn set_icount(&mut self, value: u64) {
        self.vm.cpu.icount = value;
    }

    #[getter]
    fn get_exception_value(&self) -> u64 {
        self.vm.cpu.exception.value
    }

    #[new]
    #[pyo3(signature = (
        architecture,
        jit = true,
        jit_mem = true,
        shadow_stack = true,
        recompilation = true,
        track_uninitialized = false,
        optimize_instructions = true,
        optimize_block = true,
        tracing = false,
    ))]
    fn new(
        architecture: String,
        jit: bool,
        jit_mem: bool,
        shadow_stack: bool,
        recompilation: bool,
        track_uninitialized: bool,
        optimize_instructions: bool,
        optimize_block: bool,
        tracing: bool,
    ) -> PyResult<Self> {
        // Prevent mixing '_' and '-'
        if architecture.split("-").count() != 1 {
            return Err(
                PyException::new_err(format!("Bad architecture format: {architecture}"))
            );
        }

        // TODO: support instantiating this multiple times
        if tracing {
            if tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_target(false)
                .try_init().is_err() {
            }
        }

        // Setup the CPU state for the target triple
        let mut config = icicle_vm::cpu::Config::from_target_triple(
            format!("{architecture}-none").as_str()
        );
        if config.triple.architecture == target_lexicon::Architecture::Unknown {
            return Err(
                PyException::new_err(format!("Unknown architecture: {architecture}"))
            );
        }

        // Configuration
        config.enable_jit = jit;
        config.enable_jit_mem = jit_mem;
        config.enable_shadow_stack = shadow_stack;
        config.enable_recompilation = recompilation;
        config.track_uninitialized = track_uninitialized;
        config.optimize_instructions = optimize_instructions;
        config.optimize_block = optimize_block;

        let vm = icicle_vm::build(&config)
            .map_err(|e| {
                PyException::new_err(format!("VM build error: {e}"))
            })?;

        // Populate the lowercase register map
        let mut regs = HashMap::new();
        let sleigh = vm.cpu.sleigh();
        for reg in &sleigh.named_registers {
            let name = sleigh.get_str(reg.name);
            regs.insert(name.to_lowercase(), reg.clone());
        }

        Ok(IcicleUnicornAPI {
            vm,
            regs,
        })
    }

    fn __str__(&mut self) -> String {
        let arch = &self.vm.cpu.arch;
        let endianness = if arch.sleigh.big_endian {
            "big endian"
        } else {
            "little endian"
        };
        format!("Icicle VM for {0:?} ({endianness})", arch.triple.architecture)
    }   
}

#[pyfunction]
fn architectures() -> PyResult<Vec<&'static str>> {
    Ok(vec![
        "i686",
        "x86_64",
        "aarch64",
    ])
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn icicle(_: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(architectures, m)?)?;
    m.add_class::<IcicleUnicornAPI>()?;
    Ok(())
}