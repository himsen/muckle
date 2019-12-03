# Muckle - the One True Key Exchange

## *Currently on `profiling` branch*

## Supported platforms

* Linux

Tested on:

* [Ubuntu 14.04, Compiler: GCC 4.8.4]
* [Amazon Linux 2, Compiler: ?]

## Dependencies

To build Muckle, the two following libraries must be build first. The source code are provided in this repository.

### mbedTLS

[Link](https://tls.mbed.org)
Version: 2.13.0 (apache license).

To build:

1. `$cd mbedtls-2.13.0*`
2. `$make`
3. `$make check`

That's it...

### PQCrypto-SIDH

[Link](https://github.com/Microsoft/PQCrypto-SIDH)
Version: 2.0

Note, the Makefile has been modified to remove the compilation of the tests files and CAT test files.

To build:

1. `$cd PQcrypto-SIDH-2.0`
2. `$make ARCH=[x64/x86/ARM/ARM64] CC=[gcc/clang] OPT_LEVEL=FAST`

where `ARCH` is the architecture , `CC` is the compiler and `OPT_LEVEL` is set to `FAST` to get assembly optimisation. You can information about your architecture on your target machine by running `$uname -m` in your terminal.

If the CPU does not support the special instructions: `MULX` and `ADC` then compile in the following way:

1. `$make ARCH=[x64/x86/ARM/ARM64] CC=[gcc/clang] OPT_LEVEL=GENERIC`

Check this by running `$cat /proc/cpuinfo`

## Build

To build:

1. Modify port constant `MUCKLE_PORT` (in `muckle_initiator.c` and in `muckle_responder.c`) to the port the responder is launched (defaut: `9001`).
2. Modify responder IP constant `MUCKLE_RESPONDER` (in `muckle_initiator.c`) to the IP the responder is lauched (default: `127.0.0.1`).
3. Modify responder listen interface constant `MUCKLE_LISTEN_INTERFACE` (in `muckle_responder.c`) to the interface you want the responder to listen (default: `INADDR_ANY`).
4. `$make`

## Run

Start responder

1. On responder machine: `$./muckle_responder`.

Start initiator, which will conduct the profiling automatically.

1. On initiator machine: `$./muckle_initiator`

## Profiling

The profiling is done using [minitrace](https://github.com/hrydgard/minitrace). To view the results go to chrome's build-in trace viewer: chrome://tracing. The output file containing the trace is named `trace.log`.

Note that there is no profiling on the responder side. This is because the initiator and responder shares the same functions.

## Contributors

* Torben Hansen (Royal Holloway, University of London)
* Benjamin Dowling (Royal Holloway, University of London)
