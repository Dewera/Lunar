using System;

namespace Lunar
{
    /// <summary>
    /// Defines actions that the mapper should take during the mapping process
    /// </summary>
    [Flags]
    public enum MappingFlags
    {
        /// <summary>
        /// Default value
        /// </summary>
        None = 0,
        /// <summary>
        /// Specifies that the header region of the DLL should not be mapped
        /// </summary>
        DiscardHeaders = 1,
        /// <summary>
        /// Specifies that the entry point of any TLS callbacks and the DLL should not be called
        /// </summary>
        SkipInitialisationRoutines = 2
    }
}