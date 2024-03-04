use himitsu::config::HimitsuConfiguration;

use std::env;

use tokio::runtime::Handle;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let socket_path = args.get(1).map(|x| x.to_owned());
    let config_path = args.get(2).map(|x| x.to_owned()).unwrap_or_default();

    let config = match HimitsuConfiguration::new_from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Using default configuration because error reading configuration file: {}", e);
            HimitsuConfiguration::default()
        }
    };

    let handle = Handle::current();
    let himitsu = himitsu::start_himitsu(handle, socket_path, config).unwrap();
    himitsu.join().await;
}
