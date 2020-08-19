using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Xunit;

namespace Lunar.Tests
{
    [Collection("LibraryMapper Tests")]
    public sealed class X64Tests : IDisposable
    {
        private readonly string _testBinaryDirectory;

        private readonly Process _process;

        public X64Tests()
        {
            _testBinaryDirectory = Path.GetFullPath(@"..\..\..\TestBinaries\x64");

            _process = new Process {StartInfo = {FileName = Path.Combine(_testBinaryDirectory, "Executable.exe"), UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden}};

            _process.Start();

            Thread.Sleep(10);
        }

        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        [Fact]
        public void TestMapBasic()
        {
            var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectory, "Basic.dll"));

            libraryMapper.MapLibrary();

            Assert.NotEqual(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestMapException()
        {
            var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectory, "Exception.dll"));

            libraryMapper.MapLibrary();

            Assert.NotEqual(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestMapTlsCallBack()
        {
            var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectory, "TlsCallBack.dll"));

            libraryMapper.MapLibrary();

            Assert.NotEqual(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestUnmapBasic()
        {
            var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectory, "Basic.dll"));

            libraryMapper.MapLibrary();

            libraryMapper.UnmapLibrary();

            Assert.Equal(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestUnmapException()
        {
            var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectory, "Exception.dll"));

            libraryMapper.MapLibrary();

            libraryMapper.UnmapLibrary();

            Assert.Equal(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestUnmapTlsCallBack()
        {
            var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectory, "TlsCallBack.dll"));

            libraryMapper.MapLibrary();

            libraryMapper.UnmapLibrary();

            Assert.Equal(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }
    }
}