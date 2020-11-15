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
        /// Default flag
        /// </summary>
        None = 0,
        /// <summary>
        /// Specifies that the header region of the DLL should not be mapped
        /// </summary>
        DiscardHeaders = 1,
        /// <summary>
        /// Specifies that any TLS callbacks and DllMain should not be called
        /// </summary>
        SkipInitialisationRoutines = 2
    }
}