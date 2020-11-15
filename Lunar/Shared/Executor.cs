using System;

namespace Lunar.Shared
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