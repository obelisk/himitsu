use std::ffi::{c_char, CStr};

use crate::{config::HimitsuConfiguration, HimitsuInstance};

pub struct HimitsuRuntime {
    instance: HimitsuInstance,
    runtime: tokio::runtime::Runtime,
}

#[no_mangle]
pub unsafe extern "C" fn start_himitsu(socket_path: *const c_char) -> *const HimitsuRuntime {
    println!("Requested To Start Himitsu");
    let sp = CStr::from_ptr(socket_path);
    let socket_path = match sp.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
    };

    let runtime = tokio::runtime::Runtime::new().unwrap();
    println!("Got a runtime instance. Starting Himitsu...");
    let instance = crate::start_himitsu(
        runtime.handle().clone(),
        Some(socket_path),
        HimitsuConfiguration::default(),
    );

    println!("Starting");
    let instance: HimitsuInstance = match instance {
        Err(_) => return std::ptr::null(),
        Ok(i) => i,
    };

    let runtime = HimitsuRuntime { instance, runtime };

    Box::into_raw(Box::new(runtime))
}

#[no_mangle]
pub unsafe extern "C" fn stop_himitsu(instance_ptr: *mut HimitsuRuntime) -> bool {
    println!("Attempting to stop Himitsu");
    let instance = Box::from_raw(instance_ptr);
    let sender = instance.instance.term_sender.clone();
    instance.runtime.spawn(async move {
        println!("Sending shutdown message");
        sender.send(None).await.unwrap();
        println!("Sent shutdown message");
    });

    true
}
