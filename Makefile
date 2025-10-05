AS      = aarch64-linux-gnu-as
LD      = aarch64-linux-gnu-ld
QEMU    = qemu-aarch64

# Flags opcionales (-g para depuración, -march explícito)
ASFLAGS = -g -march=armv8-a
LDFLAGS =

OBJ     = aes_main.o
TARGET  = aes

all: $(TARGET)

$(TARGET): $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $^

%.o: %.s constants.s
	$(AS) $(ASFLAGS) -o $@ $<

run: $(TARGET)
	$(QEMU) ./$(TARGET)


clean:
	rm -f *.o $(TARGET)
