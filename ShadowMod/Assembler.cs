using System;
using System.Collections.Generic;

namespace ShadowMod
{
    public class Assembler
    {
        private readonly List<byte> _asm = new List<byte>();


        public void PushRax() => _asm.Add(50);
        public void PushRcx() => _asm.Add(51);
        public void PushRdx() => _asm.Add(52);
        public void PushRbx() => _asm.Add(53);
        public void PushRsp() => _asm.Add(54);
        public void PushRbp() => _asm.Add(55);
        public void PushRsi() => _asm.Add(56);
        public void PushRdi() => _asm.Add(57);
        public void PopRax() => _asm.Add(58);
        public void MovRbxRsp() => _asm.AddRange(new byte[] { 0x48, 0x89, 0xe3 });

        public void AddEsp(byte arg)
        {
            _asm.AddRange(new byte[] { 0x83, 0xC4 });
            _asm.Add(arg);
        }

        public void AddRsp(byte arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0x83, 0xC4 });
            _asm.Add(arg);
        }

        public void CallEax()
        {
            _asm.AddRange(new byte[] { 0xFF, 0xD0 });
        }

        public void CallRax()
        {
            _asm.AddRange(new byte[] { 0xFF, 0xD0 });
        }

        public void MovEax(IntPtr arg)
        {
            _asm.Add(0xB8);
            _asm.AddRange(BitConverter.GetBytes((int)arg));
        }

        public void MovRax(IntPtr arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0xB8 });
            _asm.AddRange(BitConverter.GetBytes((long)arg));
        }

        public void MovRcx(IntPtr arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0xB9 });
            _asm.AddRange(BitConverter.GetBytes((long)arg));
        }

        public void MovRdx(IntPtr arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0xBA });
            _asm.AddRange(BitConverter.GetBytes((long)arg));
        }

        public void MovR8(IntPtr arg)
        {
            _asm.AddRange(new byte[] { 0x49, 0xB8 });
            _asm.AddRange(BitConverter.GetBytes((long)arg));
        }

        public void MovR9(IntPtr arg)
        {
            _asm.AddRange(new byte[] { 0x49, 0xB9 });
            _asm.AddRange(BitConverter.GetBytes((long)arg));
        }

        public void MovEaxTo(IntPtr dest)
        {
            _asm.Add(0xA3);
            _asm.AddRange(BitConverter.GetBytes((int)dest));
        }

        public void MovRaxTo(IntPtr dest)
        {
            _asm.AddRange(new byte[] { 0x48, 0xA3 });
            _asm.AddRange(BitConverter.GetBytes((long)dest));
        }

        public void Push(IntPtr arg)
        {
            _asm.Add((int)arg < 128 ? (byte)0x6A : (byte)0x68);
            _asm.AddRange((int)arg <= 255 ? new[] { (byte)arg } : BitConverter.GetBytes((int)arg));
        }

        public void Return()
        {
            _asm.Add(0xC3);
        }

        public void SubRsp(byte arg)
        {
            _asm.AddRange(new byte[] { 0x48, 0x83, 0xEC });
            _asm.Add(arg);
        }

        public byte[] ToByteArray() => _asm.ToArray();
    }
}
