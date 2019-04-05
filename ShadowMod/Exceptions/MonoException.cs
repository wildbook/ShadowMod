using System;

namespace Thunderbolt.Core.Exceptions
{
    public class MonoException : Exception
    {
        public MonoException() { }
        public MonoException(string message) : base(message) { }
        public MonoException(string message, Exception inner) : base(message, inner) { }
    }
}
