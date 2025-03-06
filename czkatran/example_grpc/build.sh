set -xeo pipefail

create_grpc_proto() {
    rm -rf goclient/src/czKatranc/lb_czKatran
    mkdir -p goclient/src/czKatranc/lb_czKatran
    protoc -I protos czkatran.proto --go_out=goclient/src/czKatranc/lb_czKatran --go_grpc_out=goclient/src/czKatranc/lb_czKatran
    protoc -I protos czkatran.proto --plugin=protoc-gen-grpc=/usr/bin/grpc_cpp_plugin --cpp_out=goclient/src/czKatranc/lb_czKatran --grpc_out=goclient/src/czKatranc/lb_czKatran
}
echo '
if you see “protoc-gen-go_grpc: program not found or is not executable
Please specify a program using absolute path or make sure the program is available in your PATH system variable
--go_grpc_out: protoc-gen-go_grpc: Plugin failed with status code 1.”，you should do this:
    sudo cp /home/jianglei/go/bin/protoc-gen-go /usr/local/bin/
    sudo cp /home/jianglei/go/bin/protoc-gen-go-grpc /usr/local/bin/
'


go version 1>/dev/null
protoc --version 1>/dev/null
create_grpc_proto