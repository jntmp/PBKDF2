using System;
using System.Linq;
using System.Security.Cryptography;

namespace Crypto
{
    /// <summary>
    /// Secure, salted and hashed password management
    /// </summary>
    public class PBKDF2
    {
        private int HashSize { get; set; }
        private int SaltSize { get; set; }
        private int Iterations { get; set; }

        /// <summary>
        /// Constructor. Optionally define hash size, salt size or iterations.
        /// </summary>
        /// <param name="hashSize"></param>
        /// <param name="saltSize"></param>
        /// <param name="iterations"></param>
        public PBKDF2(int hashSize = 24, int saltSize = 24, int iterations = 1000)
        {
            this.HashSize = hashSize;
            this.SaltSize = saltSize;
            this.Iterations = iterations;
        }

        /// <summary>
        /// Encrypt a plain text password. Produces a salt for storage with hashed password.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns>The encrypted password</returns>
        public string Encrypt(string password, out string salt)
        {
            // generate a random salt
            byte[] saltArr = new byte[this.SaltSize];
            using (var csprng = new RNGCryptoServiceProvider())
                csprng.GetBytes(saltArr);

            // encrypt the password
            byte[] hash = this.ComputeHash(password, saltArr);

            salt = Convert.ToBase64String(saltArr);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// Verify a password against the stored hash and salt.
        /// </summary>
        /// <param name="hash"></param>
        /// <param name="salt"></param>
        /// <param name="password"></param>
        /// <returns>Boolean match</returns>
        public bool Verify(string hash, string salt, string password)
        {
            byte[] storedSalt = Convert.FromBase64String(salt);
            byte[] storedHash = Convert.FromBase64String(hash);

            byte[] genHash = ComputeHash(password, storedSalt);
            
            return genHash.SequenceEqual(storedHash);
        }

        /// <summary>
        /// Creates the hash.
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        private byte[] ComputeHash(string password, byte[] salt)
        {
            var hash = new byte[this.HashSize];
            using (var db = new Rfc2898DeriveBytes(password, salt, this.Iterations))
                hash = db.GetBytes(hash.Length);

            return hash;
        }
    }
}
