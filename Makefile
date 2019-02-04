all: nonced

run: nonced
	./build/nonced

test:
	go test ./...

nonced:
	go build -o build/nonced cmd/nonced/main.go

clean:
	rm -rvf build || true
