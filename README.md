## Lunar

![](https://github.com/Dewera/Lunar/workflows/Continuous%20Integration/badge.svg)

A lightweight native DLL mapping library that supports mapping directly from memory

----

### Features

- WOW64 and x64 support
- Imports and delay imports are resolved
- Relocations are performed
- Sections are mapped with the correct memory protection
- Headers are mapped with the correct memory protection
- Exception handling is setup for both SEH and C++ exceptions
- Security cookie is initialised
- Entry point and TLS callbacks are called with ProcessAttach and ProcessDetach

----

### Installation

- Install the latest stable version of Lunar using the GitHub Package Registry

----

### Getting started

The example below demonstrates a basic implementation of the library

```csharp

var libraryMapper = new LibraryMapper(process, dllBytes);

// Map the DLL into the process

libraryMapper.MapLibrary();

// Unmap the DLL from the process

libraryMapper.UnmapLibrary();

```

----

### Constructors

```csharp
LibraryMapper(Process, Memory<byte>)
```
Provides the functionality to map a DLL from memory into a remote process


```csharp
LibraryMapper(Process, string)
```

Provides the functionality to map a DLL from disk into a remote process

----

### Properties

```csharp
DllBaseAddress
```

The base address of the DLL in the remote process after it has been mapped

----

### Methods

```csharp
MapLibrary()
```

Maps the DLL into the remote process

```csharp
UnmapLibrary()
```

Unmaps the DLL from the remote process

----

### Caveats

- Attempting to inject into a system level process will require your program to be run in administrator mode
- Mapping requires the presence of a PDB for ntdll.dll, and, so, the library will automatically download the latest version of this PDB from the Microsoft symbol server and cache it in `%temp%/Lunar/PDB`

----

### Contributing

Pull requests are welcome

For large changes, please open an issue first to discuss what you would like to add