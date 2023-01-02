namespace Lunar.Helpers;

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