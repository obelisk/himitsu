use std::ffi::{c_char, CStr};

use crate::{config::HimitsuConfiguration, HimitsuInstance};

#[no_mangle]
pub unsafe extern "C" fn start_himitsu(socket_path: *const c_char) -> *const HimitsuInstance {
    let sp = CStr::from_ptr(socket_path);
    let socket_path = match sp.to_str() {
        Err(_) => return std::ptr::null(),
        Ok(s) => s.to_owned(),
    };
    
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let instance = crate::start_himitsu(runtime.handle().clone(), Some(socket_path), HimitsuConfiguration::default());

    match instance {
        Err(_) => std::ptr::null(),
        Ok(i) => Box::into_raw(Box::new(i)),
    }
}

// #[no_mangle]
// pub unsafe extern "C" fn stop_himitsu(instance_ptr: *mut HimitsuInstance) -> bool {
//     let instance = Box::from_raw(instance_ptr);
//     let shutdown_sender = instance.stop();
//     rustica_agent_instance.runtime.spawn(async move {
//         shutdown_sender.send(()).await.unwrap();
//         println!("Sent shutdown message");
//     });

//     true
// }