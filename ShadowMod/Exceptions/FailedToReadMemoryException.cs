using System;

namespace Thunderbolt.Core.Exceptions
{
    public class FailedToReadMemoryException : MemoryException
    {
        public FailedToReadMemoryException() { }
        public FailedToReadMemoryException(string message) : base(message) { }
        public FailedToReadMemoryException(Exception inner) : base("Failed to read process memory.", inner) { }
        public FailedToReadMemoryException(string message, Exception inner) : base(message, inner) { }
    }
}
