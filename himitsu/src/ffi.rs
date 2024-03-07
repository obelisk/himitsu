use std::ffi::{c_char, CStr};

use secrecy::Secret;

use crate::{config::HimitsuConfiguration, HimitsuInstance};

pub struct HimitsuRuntime {
    instance: HimitsuInstance,
    runtime: tokio::runtime::Runtime,
}

#[no_mangle]
pub unsafe extern "C" fn himitsu_start(socket_path: *const c_char) -> *const HimitsuRuntime {
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
pub unsafe extern "C" fn himitsu_start_with_url_and_key(
    socket_path: *const c_char,
    url: *const c_char,
    key: *const c_char,
) -> *const HimitsuRuntime {
    println!("Requested To Start Himitsu");
    let sp = CStr::from_ptr(socket_path);
    let socket_path = match sp.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
    };

    let url = CStr::from_ptr(url);
    let url = match url.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
    };

    let key = CStr::from_ptr(key);
    let key = match key.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Err(e) => {
            println!("Failed to create runtime: {:?}", e);
            return std::ptr::null();
        }
        Ok(r) => r,
    };

    let configuration = match HimitsuConfiguration::new_from_url(url, Some(Secret::new(key))) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed to fetch configuration: {:?}", e);
            return std::ptr::null();
        }
    };

    println!("Got a runtime instance. Starting Himitsu...");
    let instance = crate::start_himitsu(runtime.handle().clone(), Some(socket_path), configuration);

    println!("Starting");
    let instance: HimitsuInstance = match instance {
        Err(_) => return std::ptr::null(),
        Ok(i) => i,
    };

    let runtime = HimitsuRuntime { instance, runtime };

    Box::into_raw(Box::new(runtime))
}

#[no_mangle]
pub unsafe extern "C" fn himitsu_stop(instance_ptr: *mut HimitsuRuntime) -> bool {
    println!("Attempting to stop Himitsu");
    let instance = Box::from_raw(instance_ptr);
    let sender = instance.instance.term_sender.clone();
    instance.runtime.spawn(async move {
        println!("Sending shutdown message");
        sender
            .send(crate::HimitsuClientServerMessage::Shutdown)
            .await
            .unwrap();
        println!("Sent shutdown message");
    });

    true
}

#[no_mangle]
pub unsafe extern "C" fn himitsu_configuration_update(instance_ptr: *mut HimitsuRuntime) -> bool {
    println!("Attempting to update Himitsu's configuration");
    let instance = Box::from_raw(instance_ptr);
    let sender = instance.instance.term_sender.clone();
    instance.runtime.spawn(async move {
        sender
            .send(crate::HimitsuClientServerMessage::Update)
            .await
            .unwrap();
    });

    Box::leak(instance);

    true
}

#[no_mangle]
pub unsafe extern "C" fn himitsu_silence_next_check(instance_ptr: *mut HimitsuRuntime) -> bool {
    println!("Silencing The Next Himitsu Check");
    let instance = Box::from_raw(instance_ptr);
    let sender = instance.instance.term_sender.clone();
    instance.runtime.spawn(async move {
        sender
            .send(crate::HimitsuClientServerMessage::SilenceOnce)
            .await
            .unwrap();
    });

    Box::leak(instance);

    true
}
