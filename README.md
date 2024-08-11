# macho2elf

This is a project that can be used to convert simple amd64 mach-o binaries to elf. It does provide a simple mechanism for shimming some of the libc and other calls. Objective C is not supported.

It is worth noting that for example pthreads do not really need in my case to be translated as all the pthread structures are larger on macOS than glibc and as such the glibc version won't corrupt memory. The software I was porting did not make use of static initializers.

Errno is not translated which can result in some issues.

The project was written in a short amount of time and as such might contain ugly code. There are various code snippets stolen from llvm libunwind, primarily from CompactUnwinder_x86_64<A>::stepWithCompactEncodingFrameless.