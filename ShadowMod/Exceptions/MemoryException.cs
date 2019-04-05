using System;

namespace Thunderbolt.Core.Exceptions
{
    public class MemoryException : InjectorException
    {
        public MemoryException() { }
        public MemoryException(string message) : base(message) { }
        public MemoryException(string message, Exception inner) : base(message, inner) { }
    }
}
