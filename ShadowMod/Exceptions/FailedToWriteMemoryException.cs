using System;

namespace Thunderbolt.Core.Exceptions
{
    public class FailedToWriteMemoryException : MemoryException
    {
        public FailedToWriteMemoryException() { }
        public FailedToWriteMemoryException(string message) : base(message) { }
        public FailedToWriteMemoryException(Exception inner) : base("Failed to write process memory.", inner) { }
        public FailedToWriteMemoryException(string message, Exception inner) : base(message, inner) { }
    }
}
