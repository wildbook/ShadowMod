using System;

namespace ShadowMod.Exceptions
{
    public class InjectorException : Exception
    {
        public InjectorException() { }
        public InjectorException(string message) : base(message) { }
        public InjectorException(string message, Exception inner) : base(message, inner) { }
    }
}
