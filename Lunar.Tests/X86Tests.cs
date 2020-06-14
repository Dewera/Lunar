using System;
using System.Diagnostics;
using System.IO;
using Xunit;

namespace Lunar.Tests
{
    public sealed class X86Tests : IDisposable
    {
        private readonly Process _process;

        public X86Tests()
        {
            var cmdFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), "cmd.exe");

            _process = new Process {StartInfo = {FileName = cmdFilePath, UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden}};

            _process.Start();
        }

        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        [Fact]
        public void TestMapBasic()
        {
            var libraryFilePath = Path.Combine(Path.GetFullPath(@"..\..\..\TestLibraries\x86"), "Basic.dll");

            var libraryMapper = new LibraryMapper(_process, libraryFilePath);

            libraryMapper.MapLibrary();

            Assert.NotEqual(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestMapException()
        {
            var libraryFilePath = Path.Combine(Path.GetFullPath(@"..\..\..\TestLibraries\x86"), "Exception.dll");

            var libraryMapper = new LibraryMapper(_process, libraryFilePath);

            libraryMapper.MapLibrary();

            Assert.NotEqual(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestMapTlsCallBack()
        {
            var libraryFilePath = Path.Combine(Path.GetFullPath(@"..\..\..\TestLibraries\x86"), "TlsCallBack.dll");

            var libraryMapper = new LibraryMapper(_process, libraryFilePath);

            libraryMapper.MapLibrary();

            Assert.NotEqual(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestUnmapBasic()
        {
            var libraryFilePath = Path.Combine(Path.GetFullPath(@"..\..\..\TestLibraries\x86"), "Basic.dll");

            var libraryMapper = new LibraryMapper(_process, libraryFilePath);

            libraryMapper.MapLibrary();

            libraryMapper.UnmapLibrary();

            Assert.Equal(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestUnmapException()
        {
            var libraryFilePath = Path.Combine(Path.GetFullPath(@"..\..\..\TestLibraries\x86"), "Exception.dll");

            var libraryMapper = new LibraryMapper(_process, libraryFilePath);

            libraryMapper.MapLibrary();

            libraryMapper.UnmapLibrary();

            Assert.Equal(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Fact]
        public void TestUnmapTlsCallBack()
        {
            var libraryFilePath = Path.Combine(Path.GetFullPath(@"..\..\..\TestLibraries\x86"), "TlsCallBack.dll");

            var libraryMapper = new LibraryMapper(_process, libraryFilePath);

            libraryMapper.MapLibrary();

            libraryMapper.UnmapLibrary();

            Assert.Equal(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }
    }
}