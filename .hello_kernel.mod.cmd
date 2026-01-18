savedcmd_hello_kernel.mod := printf '%s\n'   hello_kernel.o | awk '!x[$$0]++ { print("./"$$0) }' > hello_kernel.mod
