## Lunar

![](https://github.com/Dewera/Lunar/workflows/Continuous%20Integration/badge.svg)

A lightweight native DLL mapping library that supports mapping directly from memory

---

### Notable features

- Control flow guard setup
- Exception handler initialisation
- Security cookie generation
- Static TLS initialisation
- SxS dependency resolution
- TLS callback execution
- WOW64 and x64 support

---

### Caveats

- The latest version of the PDB for ntdll.dll is downloaded and cached on disk by the library

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

Initialises an instance of the `LibraryMapper` class with the functionality to map a DLL from memory into a process

```c#
public LibraryMapper(Process, Memory<byte>, MappingFlags);
```

Initialises an instance of the `LibraryMapper` class with the functionality to map a DLL from disk into a process

```c#
public LibraryMapper(Process, string, MappingFlags);
```

### Properties

The base address of the DLL in the process

```c#
public IntPtr DllBaseAddress { get; }
```

### Methods

Maps the DLL into the process

```c#
public void MapLibrary();
```

Unmaps the DLL from the process

```c#
public void UnmapLibrary();
```

---

### MappingFlags Enum

Defines actions that the mapper should perform during the mapping process

```c#
[Flags]
public enum MappingFlags
```

### Fields

Default value

```c#
MappingsFlags.None
```

Specifies that the header region of the DLL should not be mapped

```c#
MappingsFlags.DiscardHeaders 
```

Specifies that the entry point of any TLS callbacks and the DLL should not be called

```c#
MappingsFlags.SkipInitialisationRoutines
```
