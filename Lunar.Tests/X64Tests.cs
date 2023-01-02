using System.Diagnostics;
using Xunit;

namespace Lunar.Tests;

[Collection("LibraryMapper Tests")]
public sealed class X64Tests : IDisposable
{
    private readonly string _testBinaryDirectoryPath;
    private readonly Process _process;

    public X64Tests()
    {
        _testBinaryDirectoryPath = Path.GetFullPath(@"..\..\..\TestBinaries\bin\x64\Release");
        _process = new Process { StartInfo = { FileName = Path.Combine(_testBinaryDirectoryPath, "Target.exe"), UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden } };
        _process.Start();

        // Wait an arbitrary amount of time (10 milliseconds) for the process to initialise

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
    [InlineData("StaticTls.dll")]
    [InlineData("TlsCallback.dll")]
    public void TestMap(string dllName)
    {
        var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectoryPath, dllName));
        libraryMapper.MapLibrary();

        Assert.NotEqual(0, libraryMapper.DllBaseAddress);
    }

    [Theory]
    [InlineData("Basic.dll")]
    [InlineData("Exception.dll")]
    [InlineData("StaticTls.dll")]
    [InlineData("TlsCallback.dll")]
    public void TestUnmap(string dllName)
    {
        var libraryMapper = new LibraryMapper(_process, Path.Combine(_testBinaryDirectoryPath, dllName));
        libraryMapper.MapLibrary();
        libraryMapper.UnmapLibrary();

        Assert.Equal(0, libraryMapper.DllBaseAddress);
    }
}