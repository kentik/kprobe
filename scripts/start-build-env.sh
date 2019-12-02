set -e
docker build -t kprobe-build -f build/Dockerfile .
docker run -it -v"$(pwd)":/work --volume $SSH_AUTH_SOCK:/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent kprobe-build
