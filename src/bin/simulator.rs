use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn main() {
    process_engine::run(async |mut leader, mut sock| {
        // Send the command we want to run to the child process
        let command = b"/bin/sh";
        let _ = sock.write(&command.len().to_ne_bytes()).await.unwrap();
        let _ = sock.write(command).await.unwrap();

        let _ = leader
        .write(
            b"touch hello_world.txt\ndate >> hello_world.txt\ncat hello_world.txt\necho \"DONE\"\n",
        )
        .await
        .unwrap();

        let mut buf = vec![0; 1024];
        // loop forever so we don't exit
        loop {
            let read_len = leader.read(&mut buf).await.unwrap();
            println!(
                "OUTPUT: {}",
                String::from_utf8(buf[..read_len].to_vec()).unwrap()
            );
            tokio::task::yield_now().await;
        }
    })
}
