namespace ShadowMod
{
    public enum WaitResult : uint
    {
        WAIT_ABANDONED = 0x00000080,
        WAIT_OBJECT_0 = 0x00000000,
        WAIT_TIMEOUT = 0x00000102,
        WAIT_FAILED = 0xFFFFFFFF
    }
}