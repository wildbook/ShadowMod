using System;

namespace Thunderbolt.Core.Exceptions
{
    public class InjectorException : Exception
    {
        public InjectorException() { }
        public InjectorException(string message) : base(message) { }
        public InjectorException(string message, Exception inner) : base(message, inner) { }
    }
}
