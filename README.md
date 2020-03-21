## Lunar

![](https://github.com/Dewera/Lunar/workflows/Continuous%20Integration/badge.svg)

A lightweight native DLL mapping library that supports mapping directly from memory

----

### Features

- WOW64 and x64 support
- Imports and delay imports are resolved
- Necessary relocations are performed
- Image sections are mapped with the correct page protection
- Security cookie is initialised
- Exception handling is set up for both SEH and C++ exceptions
- Entry point and TLS callbacks are called with ProcessAttach and ProcessDetach

----

### Getting started

The example below demonstrates a simple implementation of the library

```c#

var libraryMapper = new LibraryMapper(process, dllBytes);

// Map the DLL into the process

libraryMapper.MapLibrary();

// Unmap the DLL from the process

libraryMapper.UnmapLibrary();

```

----

### Constructors

```c#
LibraryMapper(Process, Memory<byte>)
```
Provides the functionality to map a DLL from memory into a remote process


```c#
LibraryMapper(Process, string)
```

Provides the functionality to map a DLL from disk into a remote process

----

### Properties

```c#
DllBaseAddress
```

The base address of the DLL in the remote process after it has been mapped

----

### Methods

```c#
MapLibrary()
```

Maps the DLL into the remote process

```c#
UnmapLibrary()
```

Unmaps the DLL from the remote process

----

### Caveats

- Mapping requires the presence of a PDB for ntdll.dll, and, so, the library will automatically download the latest version of this PDB from the Microsoft symbol server and cache it in `%appdata%/Lunar/Dependencies`
