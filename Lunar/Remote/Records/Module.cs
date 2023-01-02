using Lunar.PortableExecutable;

namespace Lunar.Remote.Records;

internal sealed record Module(nint Address, PeImage PeImage);