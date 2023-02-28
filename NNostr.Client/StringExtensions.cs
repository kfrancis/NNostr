using NBitcoin.Secp256k1;
using System.Text;

namespace NNostr.Client
{
    public static class Extensions
    {
        public static string ToHex(this byte[] bytes)
        {
            if (bytes is null)
            {
                throw new ArgumentNullException(nameof(bytes));
            }

            var builder = new StringBuilder();
            foreach (var t in bytes)
            {
                builder.Append(t.ToHex());
            }

            return builder.ToString();
        }

        public static string ToHex(this Span<byte> bytes)
        {
            var builder = new StringBuilder();
            foreach (var t in bytes)
            {
                builder.Append(t.ToHex());
            }

            return builder.ToString();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1305:Specify IFormatProvider", Justification = "<Pending>")]
        private static string ToHex(this byte b)
        {
            return b.ToString("x2");
        }
    }

    public static class StringExtensions
    {
        public static string ComputeBIP340Signature(this string rawData, ECPrivKey privKey)
        {
            Span<byte> buf = stackalloc byte[64];
            using var sha256 = System.Security.Cryptography.SHA256.Create();

            sha256.TryComputeHash(Encoding.UTF8.GetBytes(rawData), buf, out _);
            privKey.SignBIP340(buf[..32]).WriteToSpan(buf);

            return buf.ToHex();
        }

        public static byte[] ComputeSha256Hash(this string rawData)
        {
            // Create a SHA256
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            // ComputeHash - returns byte array
            return sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
        }
    }
}