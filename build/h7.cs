using System;
class P
{
    static void Main(string[] a)
    {
        Console.WriteLine("REACHED-ENTRY");
        Console.WriteLine("ARGS-LEN=" + (a == null ? -1 : a.Length));
        if (a != null) foreach (var s in a) Console.WriteLine("ARG=" + s);
    }
}
