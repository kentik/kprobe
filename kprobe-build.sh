cargo build --release --target x86_64-unknown-linux-musl
scp target/x86_64-unknown-linux-musl/release/kprobe mikek@192.168.2.203:/home/mikek/bin/

