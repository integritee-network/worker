#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use std::prelude::v1::*;
use std::sync::SgxMutex;
use std::ptr;
use sgxwasm::{SpecDriver, boundary_value_to_runtime_value, result_covert};
use sgx_types::*;
use std::slice;
use wasmi::{ModuleInstance, ImportsBuilder, RuntimeValue, Error as InterpreterError, Module, NopExternals};

lazy_static!{
    static ref SPECDRIVER: SgxMutex<SpecDriver> = SgxMutex::new(SpecDriver::new());
}

#[no_mangle]
pub extern "C"
fn sgxwasm_init() -> sgx_status_t {
    let mut sd = SPECDRIVER.lock().unwrap();
    *sd = SpecDriver::new();
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C"
fn sgxwasm_run_action(req_bin : *const u8, req_length: usize,
                      result_bin : *mut u8, result_max_len: usize) -> sgx_status_t {
    println!("[Enclave] sgxwasm_run_action() called");
    let req_slice = unsafe { slice::from_raw_parts(req_bin, req_length) };
    let action_req: sgxwasm::SgxWasmAction = serde_json::from_slice(req_slice).unwrap();

    let response;
    let return_status;

    match action_req {
        sgxwasm::SgxWasmAction::Invoke{module,field,args}=> {
            let args = args.into_iter()
                           .map(|x| boundary_value_to_runtime_value(x))
                           .collect::<Vec<RuntimeValue>>();
            let _module = Module::from_buffer(module.unwrap()).unwrap();
            let instance =
                ModuleInstance::new(
                    &_module,
                    &ImportsBuilder::default()
                )
                .expect("failed to instantiate wasm module")
                .assert_no_start();

            let r = instance.invoke_export(&field, &args, &mut NopExternals);

            //let r = wasm_invoke(module, field, args);
            println!("[Enclave] wasm_invoke successful");
            let r = result_covert(r);
            println!("[Enclave] result_covert successful");
            response = serde_json::to_string(&r).unwrap();
            println!("[Enclave] serialization successful");
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
               }
            }
        },

        sgxwasm::SgxWasmAction::Get{module,field} => {
            /*
            let r = wasm_get(module, field);
            let r = result_covert(r);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_v) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
                }
            }
            */
            return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
            response = "not supported".to_string();
        },
        sgxwasm::SgxWasmAction::LoadModule{name,module} => {
            /*
            let r = wasm_load_module(name.clone(), module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(_) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_LOAD_MODULE_ERROR;
                }
            }
            */
            return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
            response = "not supported".to_string();
        },
        sgxwasm::SgxWasmAction::TryLoad{module} => {
            /*
            let r = wasm_try_load(module);
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_TRY_LOAD_ERROR;
                }
            }
            */
            return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
            response = "not supported".to_string();
        },
        sgxwasm::SgxWasmAction::Register{name, as_name} => {
            /*
            let r = wasm_register(&name, as_name.clone());
            response = serde_json::to_string(&r).unwrap();
            match r {
                Ok(()) => {
                    return_status = sgx_status_t::SGX_SUCCESS;
                },
                Err(_x) => {
                    return_status = sgx_status_t::SGX_ERROR_WASM_REGISTER_ERROR;
                }
            }
            */
            return_status = sgx_status_t::SGX_ERROR_WASM_INTERPRETER_ERROR;
            response = "not supported".to_string();
        }

    }

    //println!("len = {}, Response = {:?}", response.len(), response);

    if response.len() < result_max_len {
        unsafe {
            ptr::copy_nonoverlapping(response.as_ptr(),
                                     result_bin,
                                     response.len());
        }
        return return_status;
    }
    else{
        //println!("Result len = {} > buf size = {}", response.len(), result_max_len);
        return sgx_status_t::SGX_ERROR_WASM_BUFFER_TOO_SHORT;
    }
}
