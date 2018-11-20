using System;
using MimeKit;
using Heijden.DNS;

namespace dkimstuff
{
    class Program
    {
        static void Main(string[] args)
        {
            var message = MimeMessage.Load(args[0]);
            var locator = new DkimPublicKeyLocator();
            var index = message.Headers.IndexOf(HeaderId.DkimSignature);

            if (index == -1)
            {
                Console.WriteLine("NO SIGNATURE");
            }

            var dkim = message.Headers[index];

            if (message.Verify(dkim, locator))
            {
                // the DKIM-Signature header is valid!
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("VALID");
                Console.ResetColor();
            }
            else
            {
                // the DKIM-Signature is invalid!
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("INVALID");
                Console.ResetColor();
            }
        }
    }
}
