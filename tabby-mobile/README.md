## Tabby Portable Build
#### Strong, Fast, and Portable Cryptographic Signatures, Handshakes, and Password Authentication

See the full documentation at [https://github.com/catid/tabby](https://github.com/catid/tabby).

#### Quick Setup

To quickly evaluate Tabby for your application, just include the files in this
folder and use the API described in "tabby.h".

To best incorporate Tabby, edit the Makefile to build for your target and link
the static library to your application.

The GCC and Clang compilers are supported.  The Intel C++ Compiler and Microsoft
Visual C++ compilers are not supported because they do not support emulated
128-bit datatypes.  To integrate this library into a project for a compiler
other than GCC/Clang, generate a static library and link it in that way.

#### XCode/iOS

Just add the files to your project and #import "tabby.h".

#### Android

Just add the files to your Android.mk and #include "tabby.h".

