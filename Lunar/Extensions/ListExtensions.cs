using System;
using System.Collections.Generic;

namespace Lunar.Extensions
{
    internal static class ListExtensions
    {
        internal static void AddRange<T>(this List<T> list, Span<T> span)
        {
            foreach (var element in span)
            {
                list.Add(element);
            }
        }
    }
}