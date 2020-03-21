using System;
using System.IO;
using System.Threading;
using Xunit;

namespace Lunar.Tests
{
    public sealed class X64Tests : MappingTester
    {
        public X64Tests() : base(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe"), Path.Combine(Path.GetFullPath(@"..\..\..\Dll"), "X64.dll")) { }
        
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