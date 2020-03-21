using System;
using System.IO;
using Xunit;

namespace Lunar.Tests
{
    public class X86Tests : MappingTester
    {
        public X86Tests() : base(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe"), Path.Combine(Path.GetFullPath(@"..\..\..\Dll"), "X64.dll")) { }
        
        [Fact]
        public void TestMap()
        {
            LibraryMapper.MapLibrary();

            Assert.NotEqual(LibraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestUnmap()
        {
            LibraryMapper.MapLibrary();

            LibraryMapper.UnmapLibrary();

            Assert.Equal(LibraryMapper.DllBaseAddress, IntPtr.Zero);
        }
    }
}