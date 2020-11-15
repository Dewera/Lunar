using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Xunit;

namespace Lunar.Tests
{
    [Collection("LibraryMapper Tests")]
    public sealed class X86Tests : IDisposable
    {
        private readonly string _testBinaryDirectoryPath;

        private readonly Process _process;

        public X86Tests()
        {
            _testBinaryDirectoryPath = Path.GetFullPath(@"..\..\..\TestBinaries\bin\x86\Release");

            _process = new Process {StartInfo = {FileName = Path.Combine(_testBinaryDirectoryPath, "Target.exe"), UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden}};

            _process.Start();

            Thread.Sleep(10);
        }

        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }

        [Theory]
        [InlineData("Basic.dll")]
        [InlineData("Exception.dll")]
        [InlineData("TlsCallback.dll")]
        public void TestMap(string dllName)
        {
            var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectoryPath, dllName));

            libraryMapper.MapLibrary();

            Assert.NotEqual(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }

        [Theory]
        [InlineData("Basic.dll")]
        [InlineData("Exception.dll")]
        [InlineData("TlsCallback.dll")]
        public void TestUnmap(string dllName)
        {
            var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectoryPath, dllName));

            libraryMapper.MapLibrary();

            libraryMapper.UnmapLibrary();

            Assert.Equal(libraryMapper.DllBaseAddress, IntPtr.Zero);
        }
    }
}