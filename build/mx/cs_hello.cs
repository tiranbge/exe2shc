using System;
class P
{
    static int Main(string[] args)
    {
        Console.WriteLine("CS-HELLO bits=" + (IntPtr.Size * 8) + " args=" + args.Length);
        foreach (var a in args) Console.WriteLine("  arg=" + a);
        return 4;
    }
}
