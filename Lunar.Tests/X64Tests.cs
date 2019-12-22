using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Pluto.Tests
{
    public sealed class X64Tests : IDisposable
    {
        private readonly string _dllPath;

        private readonly Process _process;

        public X64Tests()
        {
            _dllPath = Path.Combine(Path.GetFullPath(@"..\..\..\TestDll\"), "X64.dll");

            _process = new Process {StartInfo = {CreateNoWindow = true, FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe"), UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden}};

            _process.Start();

            _process.WaitForInputIdle();
        }

        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        [Fact]
        public void TestMap()
        {
            var libraryMapper = new LibraryMapper(_process, _dllPath);

            libraryMapper.MapLibrary();

            Assert.NotEqual(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestUnmap()
        {
            var libraryMapper = new LibraryMapper(_process, _dllPath);

            libraryMapper.MapLibrary();

            libraryMapper.UnmapLibrary();

            Assert.Equal(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }
    }
}