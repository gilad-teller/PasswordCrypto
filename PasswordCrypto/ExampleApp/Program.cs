using System;
using System.Security;

namespace ExampleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            //salt is a randomized string
            string salt = PasswordCrypto.PasswordCrypto.GenerateSalt();
            string hashedPassword = GetPassword(salt);
            Console.WriteLine($"Salt: {salt}");
            Console.WriteLine($"Hashed Password: {hashedPassword}");
            //store the salt with the hashed password in your database
            string secondHashedPassword = GetPassword(salt);
            Console.WriteLine($"Hashed Second Password: {secondHashedPassword}");
            //when the user enters his password to login, add the salt, hash it again, and then compare to the hashed password in your database
            //you should not be able to decrypt the password, if a user looses his password, he must create a new one.
            if (secondHashedPassword == hashedPassword)
            {
                Console.WriteLine("Passwords are identical!");
            }
            else
            {
                Console.WriteLine("Passwords are different!");
            }
            Console.ReadKey();
        }

        private static string GetPassword(string salt)
        {
            Console.Write("Enter Password: ");
            string password = Console.ReadLine();
            string hashedPassword = null;
            //secure string is disposed from memory, so it does not leave any trace in ram
            using (SecureString securedPassword = PasswordCrypto.PasswordCrypto.ToSecureString(password))
            {
                hashedPassword = PasswordCrypto.PasswordCrypto.HashPassword(securedPassword, salt);
            }
            return hashedPassword;
        }
    }
}
