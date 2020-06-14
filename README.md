## Lunar

![](https://github.com/Dewera/Lunar/workflows/Continuous%20Integration/badge.svg)

A lightweight native DLL mapping library that supports mapping directly from memory

---

### Features

- x86 and x64 support
- Direct memory mapping
- Manual exception handler initialisation
- Randomised security cookie generation
- TLS callback execution

---

### Caveats

- The presence of a PDB for ntdll.dll is needed and, hence, will be automatically downloaded and cached on disk by the library

---

### Getting started

The example below demonstrates a basic implementation of the library that maps a DLL from disk without its headers

```c#
var process = Process.GetProcessesByName("")[0];

var dllFilePath = "";

var flags = MappingFlags.DiscardHeaders;

var mapper = new LibraryMapper(process, dllFilePath, flags);

mapper.MapLibrary();
```

---

### LibraryMapper Class

#### Constructors

```c#
LibraryMapper(Process, Memory<byte>, MappingFlags)
```
Provides the functionality to map a DLL from memory into a process

```c#
LibraryMapper(Process, string, MappingFlags)
```

Provides the functionality to map a DLL from disk into a process

#### Properties

```c#
DllBaseAddress
```

The base address of the DLL in the process after it has been mapped

#### Methods

```c#
MapLibrary()
```

Maps the DLL into the process

```c#
UnmapLibrary()
```

Unmaps the DLL from the process

---

### MappingFlags Enum

#### Fields

```c#
MappingsFlags.None
```

Default flag

```c#
MappingsFlags.DiscardHeaders 
```

Specifies that the header region of the DLL should not be mapped

```c#
MappingsFlags.SkipInitialisationRoutines
```

Specifies that TLS callbacks and DllMain should not be called
