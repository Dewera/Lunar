## Lunar

![](https://github.com/Dewera/Lunar/workflows/Continuous%20Integration/badge.svg)

A lightweight native DLL mapping library that supports mapping directly from memory

----

### Features

- Imports and delay imports are resolved
- Relocations are performed
- Image sections are mapped with the correct page protection
- Exception handlers are initialised
- A security cookie is generated and initialised
- DLL entry point and TLS callbacks are called

----

### Caveats

- Mapping requires the presence of a PDB for ntdll.dll on disk. The library will automatically download the latest version of this PDB and cache it on disk.

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
Provides the functionality to map a DLL from memory into a process


```c#
LibraryMapper(Process, string)
```

Provides the functionality to map a DLL from disk into a process

----

### Properties

```c#
DllBaseAddress
```

The base address of the DLL in the process after it has been mapped

----

### Methods

```c#
MapLibrary()
```

Maps the DLL into the process

```c#
UnmapLibrary()
```

Unmaps the DLL from the process
