typedef unsigned long size_t;

struct NR {
    static const size_t WRITE = 1;
    static const size_t MMAP = 9;
    static const size_t MUNMAP = 11;
    static const size_t EXIT = 60;
};

int main();

extern "C" void *malloc(size_t size);
extern "C" void free(void *ptr);

extern "C" void *memcpy(void *dest, const void *src, size_t n);

extern "C" size_t strlen(const char *str);
extern "C" char *strcpy(char *dst, const char *src);

size_t __syscall(size_t, size_t, size_t, size_t, size_t, size_t);
extern "C" size_t write(int, const void*, size_t);
extern "C" void *mmap(void *addr, size_t len, int prot, int flags, int fields,
        signed long off);
extern "C" int munmap(void *addr, size_t len);
extern "C" [[noreturn]] void exit(int);

void *operator new(size_t count);
void *operator new[](size_t count);

void operator delete(void *ptr) noexcept;
void operator delete[](void *ptr) noexcept;

void operator delete(void *ptr, size_t count) noexcept;
void operator delete[](void *ptr, size_t count) noexcept;

asm(
        ".globl _start\n"
        "_start:\n"
        "endbr64\n"
        "wrfsbase %rsp\n"
        "call main\n"
        "mov %rax, %rdi\n"
        "call exit\n"
    );

class S {
public:
    explicit S(const char *str = "", size_t len = 0)
        : len_(len == 0 ? strlen(str) : len), str_(new char[this->len_ + 1]) {
            strcpy(this->str_, str);
    }

    ~S() {
        delete [] this->str_;
    }

    S(const S& other)
        : len_(other.len_), str_(new char[this->len_ + 1]) {
            strcpy(this->str_, other.str_);
        }

    S& operator=(const S& other) = delete;

    S(S&& other) noexcept = delete;

    S& operator=(S&& other) noexcept = delete;

    operator const char *() const {
        return this->str_;
    }

    size_t length() {
        return this->len_;
    }

private:
    size_t len_;
    char *str_;
};

void *operator new(size_t count) {
    void *ptr = malloc(count);
    if (!ptr) {
        exit(1);
    }
    return ptr;
}

void *operator new[](size_t count) {
    void *ptr = malloc(count);
    if (!ptr) {
        exit(1);
    }
    return ptr;
}

void operator delete(void *ptr) noexcept {
    free(ptr);
}

void operator delete[](void *ptr) noexcept {
    free(ptr);
}

void operator delete(void *ptr, size_t) noexcept {
    free(ptr);
}
void operator delete[](void *ptr, size_t) noexcept {
    free(ptr);
}

void f() {
    S str{"hello world!\n"};
    write(1, str, str.length());
}

int main() {
    f();

    return 0;
}

struct BlockHeader {
    size_t size;
    BlockHeader* next;
};

static BlockHeader* allocated_blocks = nullptr;

void *malloc(size_t size) {
    if (size == 0) {
        return nullptr;
    }

    size_t page_size = 4096;

    size_t total_size = size + sizeof(BlockHeader);

    size_t aligned_size = ((total_size + page_size - 1) / page_size) * page_size;

    void* ptr = mmap(nullptr, aligned_size,
                     0x1 | 0x2 /* PROT_READ | PROT_WRITE */,
                     0x20 | 0x02 /* MAP_PRIVATE | MAP_ANONYMOUS */, -1, 0);
    if (ptr == reinterpret_cast<void*>(-1)) {
        return nullptr;
    }

    auto* header = reinterpret_cast<BlockHeader*>(ptr);
    header->size = aligned_size;
    header->next = allocated_blocks;
    allocated_blocks = header;

    return reinterpret_cast<void*>(header + 1);
}

void free(void *ptr) {
    if (ptr == nullptr) {
        return;
    }

    auto* header = reinterpret_cast<BlockHeader*>(ptr) - 1;

    if (allocated_blocks == header) {
        allocated_blocks = header->next;
    } else {
        BlockHeader* current = allocated_blocks;
        while (current && current->next != header) {
            current = current->next;
        }
        if (current) {
            current->next = header->next;
        }
    }

    munmap(header, header->size);
}

void *memcpy(void *dest, const void *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        reinterpret_cast<char*>(dest)[i] =
            reinterpret_cast<const char*>(src)[i];
    }

    return dest;
}

size_t strlen(const char *str) {
    const char *ptr = str;
    while (*ptr) ptr++;
    return ptr - str;
}

char *strcpy(char *dst, const char *src) {
    size_t len = strlen(src);
    memcpy(dst, src, len);
    return dst + len;
}

static __inline size_t __syscall(size_t n = 0, size_t a1 = 0, size_t a2 = 0,
        size_t a3 = 0, size_t a4 = 0, size_t a5 = 0, size_t a6 = 0) {
    size_t ret;
    register size_t r10 __asm__("r10") = a4;
    register size_t r8 __asm__("r8") = a5;
    register size_t r9 __asm__("r9") = a6;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
            "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

size_t write(int fd, const void* buf, size_t count) {
    return __syscall(NR::WRITE, fd, reinterpret_cast<size_t>(buf), count);
}

void *mmap(void *addr, size_t len, int prot, int flags, int fields,
        signed long off) {
    return reinterpret_cast<void*>(__syscall(NR::MMAP,
                reinterpret_cast<size_t>(addr), len, prot, flags, fields,
                off));
}

int munmap(void *addr, size_t len) {
    return __syscall(NR::MUNMAP, reinterpret_cast<size_t>(addr), len);
}

[[noreturn]]
void exit(int n) {
    __syscall(NR::EXIT, n);

    __builtin_unreachable();
}

extern "C" [[noreturn]] void __stack_chk_fail() {
    exit(1);
}
