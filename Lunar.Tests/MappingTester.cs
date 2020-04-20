using System;
using System.Diagnostics;

namespace Lunar.Tests
{
    public abstract class MappingTester : IDisposable
    {
        internal LibraryMapper LibraryMapper { get; }

        private readonly Process _process;

        protected MappingTester(string processFilePath, string dllFilePath)
        {
            var processStartInfo = new ProcessStartInfo {CreateNoWindow = true, FileName = processFilePath, UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden};

            _process = new Process {StartInfo = processStartInfo};

            _process.Start();

            _process.WaitForInputIdle();

            LibraryMapper = new LibraryMapper(_process, dllFilePath);
        }

        public void Dispose()
        {
            _process.Kill();

            _process.Dispose();
        }
    }
}