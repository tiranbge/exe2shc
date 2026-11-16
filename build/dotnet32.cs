using System;
class P {
    static int Main(string[] args) {
        Console.WriteLine("DOTNET32 ARGC=" + args.Length);
        foreach (var a in args) Console.WriteLine("ARG=" + a);
        return 0;
    }
}
