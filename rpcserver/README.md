run cmd
```
protoc -I=. --go_out=. ./server.proto
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative server.proto
```
in current directory after you change the _server.proto_ file