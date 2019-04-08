using System.Runtime.InteropServices;

namespace ShadowMod.Native
{
    // x64 m128a
    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong High;
        public long  Low;

        public override string ToString() => $"High:{High}, Low:{Low}";
    }
}