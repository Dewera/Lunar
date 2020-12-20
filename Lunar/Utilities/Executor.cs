using System;

namespace Lunar.Utilities
{
    internal static class Executor
    {
        internal static void IgnoreExceptions(Action operation)
        {
            try
            {
                operation.Invoke();
            }

            catch
            {
                // Ignore
            }
        }
    }
}