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
	./build/nonced nonce block --id 0000000000000778a22c0c0ccb535f6dcd748f6cd4debb1131d4de3a14cb04e6

test:
	go test ./...
