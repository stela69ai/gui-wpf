using System;
using System.IO;
using System.Security.Cryptography;

namespace SimpleCrypt.Functions.Encryption.ChaCha20
{
    public static class ChaCha20
    {
        private const int KeySize = 32; // 256-bit key
        private const int NonceSize = 12; // 96-bit nonce

        public static void EncryptFile(string inputFile, string outputFile, string password)
        {
            using (var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                // Generate random salt and nonce
                byte[] salt = GenerateRandomBytes(16);
                byte[] nonce = GenerateRandomBytes(NonceSize);

                // Derive key from password
                using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
                {
                    byte[] key = deriveBytes.GetBytes(KeySize);

                    // Write salt and nonce to output
                    outputStream.Write(salt, 0, salt.Length);
                    outputStream.Write(nonce, 0, nonce.Length);

                    // Use ChaCha20 engine directly
                    var engine = new ChaCha20Engine();
                    engine.Initialize(key, nonce, 0);

                    // Encrypt the data
                    byte[] buffer = new byte[4096];
                    byte[] encryptedBuffer = new byte[4096];
                    int bytesRead;
                    ulong counter = 0;

                    while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        engine.GenerateKeyStream(encryptedBuffer, counter, bytesRead);

                        for (int i = 0; i < bytesRead; i++)
                        {
                            encryptedBuffer[i] = (byte)(buffer[i] ^ encryptedBuffer[i]);
                        }

                        outputStream.Write(encryptedBuffer, 0, bytesRead);
                        counter += (ulong)Math.Ceiling(bytesRead / 64.0);
                    }
                }
            }
        }

        public static void DecryptFile(string inputFile, string outputFile, string password)
        {
            using (var inputStream = new FileStream(inputFile, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputFile, FileMode.Create, FileAccess.Write))
            {
                // Read salt and nonce
                byte[] salt = new byte[16];
                byte[] nonce = new byte[NonceSize];
                inputStream.Read(salt, 0, salt.Length);
                inputStream.Read(nonce, 0, nonce.Length);

                // Derive key from password
                using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256))
                {
                    byte[] key = deriveBytes.GetBytes(KeySize);

                    // Use ChaCha20 engine directly
                    var engine = new ChaCha20Engine();
                    engine.Initialize(key, nonce, 0);

                    // Decrypt the data
                    byte[] buffer = new byte[4096];
                    byte[] decryptedBuffer = new byte[4096];
                    int bytesRead;
                    ulong counter = 0;

                    while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        engine.GenerateKeyStream(decryptedBuffer, counter, bytesRead);

                        for (int i = 0; i < bytesRead; i++)
                        {
                            decryptedBuffer[i] = (byte)(buffer[i] ^ decryptedBuffer[i]);
                        }

                        outputStream.Write(decryptedBuffer, 0, bytesRead);
                        counter += (ulong)Math.Ceiling(bytesRead / 64.0);
                    }
                }
            }
        }

        private static byte[] GenerateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }

    // ChaCha20 Core Engine
    internal class ChaCha20Engine
    {
        private uint[] _state;
        private bool _initialized;

        public void Initialize(byte[] key, byte[] nonce, ulong counter)
        {
            if (key.Length != 32) throw new ArgumentException("Key must be 256 bits");
            if (nonce.Length != 12) throw new ArgumentException("Nonce must be 96 bits");

            _state = new uint[16];

            // Constants
            _state[0] = 0x61707865;  // "expa"
            _state[1] = 0x3320646e;  // "nd 3"
            _state[2] = 0x79622d32;  // "2-by"
            _state[3] = 0x6b206574;  // "te k"

            // Key
            for (int i = 0; i < 8; i++)
            {
                _state[4 + i] = BytesToUInt(key, i * 4);
            }

            // Counter
            _state[12] = (uint)counter;
            _state[13] = (uint)(counter >> 32);

            // Nonce
            _state[14] = BytesToUInt(nonce, 0);
            _state[15] = BytesToUInt(nonce, 4);

            _initialized = true;
        }

        public void GenerateKeyStream(byte[] output, ulong counter, int length)
        {
            if (!_initialized)
                throw new InvalidOperationException("ChaCha20 not initialized");

            int blocksNeeded = (int)Math.Ceiling(length / 64.0);

            for (int block = 0; block < blocksNeeded; block++)
            {
                // Set counter for this block
                ulong currentCounter = counter + (ulong)block;
                _state[12] = (uint)currentCounter;
                _state[13] = (uint)(currentCounter >> 32);

                uint[] workingState = (uint[])_state.Clone();

                // 20 rounds (10 double rounds)
                for (int i = 0; i < 10; i++)
                {
                    QuarterRound(ref workingState[0], ref workingState[4], ref workingState[8], ref workingState[12]);
                    QuarterRound(ref workingState[1], ref workingState[5], ref workingState[9], ref workingState[13]);
                    QuarterRound(ref workingState[2], ref workingState[6], ref workingState[10], ref workingState[14]);
                    QuarterRound(ref workingState[3], ref workingState[7], ref workingState[11], ref workingState[15]);

                    QuarterRound(ref workingState[0], ref workingState[5], ref workingState[10], ref workingState[15]);
                    QuarterRound(ref workingState[1], ref workingState[6], ref workingState[11], ref workingState[12]);
                    QuarterRound(ref workingState[2], ref workingState[7], ref workingState[8], ref workingState[13]);
                    QuarterRound(ref workingState[3], ref workingState[4], ref workingState[9], ref workingState[14]);
                }

                // Add initial state to result
                for (int i = 0; i < 16; i++)
                {
                    workingState[i] += _state[i];
                }

                // Convert to byte array for this block
                int bytesToCopy = Math.Min(64, length - (block * 64));
                for (int i = 0; i < bytesToCopy / 4; i++)
                {
                    UIntToBytes(workingState[i], output, (block * 64) + (i * 4));
                }
            }
        }

        private void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            a += b; d = RotateLeft(d ^ a, 16);
            c += d; b = RotateLeft(b ^ c, 12);
            a += b; d = RotateLeft(d ^ a, 8);
            c += d; b = RotateLeft(b ^ c, 7);
        }

        private uint RotateLeft(uint value, int offset)
        {
            return (value << offset) | (value >> (32 - offset));
        }

        private uint BytesToUInt(byte[] data, int offset)
        {
            return ((uint)data[offset]) |
                   ((uint)data[offset + 1] << 8) |
                   ((uint)data[offset + 2] << 16) |
                   ((uint)data[offset + 3] << 24);
        }

        private void UIntToBytes(uint value, byte[] data, int offset)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }
    }
}