clang source/spawner.c -o source/spawner
clang source/main.c -o source/main
clang source/child.c -dynamiclib -o source/child.dylib
