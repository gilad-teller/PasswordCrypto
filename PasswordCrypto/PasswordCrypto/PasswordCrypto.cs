using System;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace PasswordCrypto
{
    /// <summary>
    /// Handle Password security
    /// </summary>
    public class PasswordCrypto
    {
        /// <summary>
        /// Generates a cryptography secured random string
        /// </summary>
        /// <returns>Salt string (safe for database)</returns>
        public static string GenerateSalt()
        {
            RandomNumberGenerator r = RandomNumberGenerator.Create();
            byte[] salt = new byte[20];
            r.GetBytes(salt);
            string str = BytesToString(salt);
            return str;
        }

        /// <summary>
        /// Hash a password with it's salt
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="salt">Salt</param>
        /// <returns>Password+Salt after hashing (Safe for database)</returns>
        public static string HashPassword(SecureString password, string salt)
        {
            SHA512 hash = SHA512.Create();
            byte[] bytes = Encoding.UTF8.GetBytes(ToInsecureString(password) + salt);
            byte[] hashedBytes = hash.ComputeHash(bytes);
            string str = BytesToString(hashedBytes);
            return str;
        }

        /// <summary>
        /// Generate a SecureString from regular string
        /// </summary>
        /// <param name="input">Insecure string</param>
        /// <returns>Input as SecuredString</returns>
        public static SecureString ToSecureString(string input)
        {
            SecureString secure = new SecureString();
            foreach (char c in input)
            {
                secure.AppendChar(c);
            }
            secure.MakeReadOnly();
            return secure;
        }

        /// <summary>
        /// Generate regular string from SecureString
        /// </summary>
        /// <param name="input">SecureString input</param>
        /// <returns>Original string</returns>
        private static string ToInsecureString(SecureString input)
        {
            string returnValue = string.Empty;
            IntPtr ptr = System.Runtime.InteropServices.Marshal.SecureStringToBSTR(input);
            try
            {
                returnValue = System.Runtime.InteropServices.Marshal.PtrToStringBSTR(ptr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeBSTR(ptr);
            }
            return returnValue;
        }

        /// <summary>
        /// String representation of a byte array
        /// </summary>
        /// <param name="array">Byte array</param>
        /// <returns>String of the byte array</returns>
        private static string BytesToString(byte[] array)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < array.Length; i++)
            {
                sb.Append(array[i].ToString("X2"));
            }
            return sb.ToString();
        }
    }
}
