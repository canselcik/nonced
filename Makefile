BUILD_DIR=./build
NONCED_BIN_TARGET=$(BUILD_DIR)/nonced

all: nonced


run: nonced
	$(NONCED_BIN_TARGET)
nonced:
	go build -o $(NONCED_BIN_TARGET) ./cmd/nonced/main.go


clean:
	@rm -rvf $(BUILD_DIR) || true

fmt:
	@go fmt ./...


demo:
	./build/nonced nonce tx --id 9ec4bc49e828d924af1d1029cacf709431abbde46d59554b62bc270e3b29c4b1

test:
	go test ./...
