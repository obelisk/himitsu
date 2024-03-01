use himitsu::config::HimitsuConfiguration;

use std::env;

use tokio::runtime::Handle;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let socket_path = args.get(1).map(|x| x.to_owned());

    let handle = Handle::current();
    let himitsu = himitsu::start_himitsu(handle, socket_path, HimitsuConfiguration::default()).unwrap();
    himitsu.join().await;
}
