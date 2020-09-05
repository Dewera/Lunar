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

- A PDB for ntdll.dll is downloaded and cached on disk by the library

---

### Getting started

The example below demonstrates a basic implementation of the library

```c#
var process = Process.GetProcessesByName("")[0];

var dllFilePath = "";

var flags = MappingFlags.DiscardHeaders;

var mapper = new LibraryMapper(process, dllFilePath, flags);

mapper.MapLibrary();
```

---

### LibraryMapper Class

Provides the functionality to map a DLL from disk or memory into a process

```c#
public sealed class LibraryMapper
```

### Constructors

Provides the functionality to map a DLL from memory into a process

```c#
LibraryMapper(Process, Memory<byte>, MappingFlags)
```

Provides the functionality to map a DLL from disk into a process

```c#
LibraryMapper(Process, string, MappingFlags)
```

### Properties

The base address of the DLL in the process after it has been mapped

```c#
DllBaseAddress
```

### Methods

Maps the DLL into the process

```c#
MapLibrary()
```

Unmaps the DLL from the process

```c#
UnmapLibrary()
```

---

### MappingFlags Enum

Defines actions that the mapper should take during mapping

```c#
[Flags]
public enum MappingFlags
```

### Fields

Default flag

```c#
MappingsFlags.None
```

Specifies that the header region of the DLL should not be mapped

```c#
MappingsFlags.DiscardHeaders 
```

Specifies that TLS callbacks and DllMain should not be called

```c#
MappingsFlags.SkipInitialisationRoutines
```
