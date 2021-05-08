macro(append_extra_cryptography_apple_libs NativeLibsExtra)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation)
    find_library(SECURITY_LIBRARY Security)

    list(APPEND ${NativeLibsExtra} ${COREFOUNDATION_LIBRARY} ${SECURITY_LIBRARY})

    # Overrides for weak linking to Swift core libraries. The Swift libraries ship
    # with OS only from macOS 10.4.4 and iOS 12.2. Additionally when targeting
    # down-level platforms the toolchain libraries specify "@rpath" based paths
    # to facilitate fallback to locally shipped Swift runtime. We don't ship
    # the runtime and just point to the system one.
    list(APPEND ${NativeLibsExtra} -L/usr/lib/swift -lobjc -weak-lswiftCore -weak-lswiftFoundation -Wl,-rpath,/usr/lib/swift)
endmacro()
