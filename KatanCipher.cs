using System;
using System.Text;

public sealed class KatanCipher
{
    private readonly int blockSizeBits;          // 32 / 48 / 64
    private readonly int blockBytes;             // 4 / 6 / 8
    private const int Rounds = 254;              // KATAN standard
    private const int KeyBits = 80;

    private readonly int x1Size, x2Size;
    private readonly int[] x1Taps; // 5 tap
    private readonly int[] x2Taps; // 6 tap

    // KATAN IR sequence (254 bit) – official
    // Not: bazı kaynaklar IR’ı 254 bit verir. Biz 254 bit kullanıyoruz.
    private static readonly bool[] IR = new bool[]
    {
        true,true,true,true,true,true,true,false,false,false,
        true,true,false,true,false,true,false,true,false,true,
        true,true,true,false,true,true,false,false,true,true,
        false,false,true,false,true,false,false,true,false,false,
        false,true,true,false,false,false,true,true,true,true,
        false,false,false,false,true,false,false,false,false,true,
        false,true,false,false,false,true,true,true,true,true,
        true,false,true,true,true,true,true,true,false,true,
        false,true,false,false,false,false,true,false,false,false,
        true,false,false,false,true,true,true,false,false,true,
        true,true,true,true,false,false,true,true,true,true,
        true,false,true,false,false,true,false,true,false,true,
        false,false,true,true,false,false,true,false,true,true,
        true,false,true,true,false,true,true,false,false,true,
        true,false,true,false,true,true,false,false,false,true,
        false,true,true,true,false,true,true,true,true,false,
        false,false,true,true,true,false,true,false,false,false,
        true,false,true,false,false,true,true,true,false,false,
        false,true,true,false,false,false,false,true,false,false,
        true,true,true,true,false,true,false,false,false,true,
        true,true,false,false,true,false,false,true,true,true,
        true,false,true,true,true,false,false,false,false,false,
        false,false,true,false,true,true,false,false,true,false,
        true,false,true,true,false,true,false,false,true,true,
        true,true,true,true,true,false,false,true,false,true,
        true,false,false,true,false
    };

    public int BlockBytes => blockBytes;

    public KatanCipher(int blockSize)
    {
        blockSizeBits = blockSize;

        switch (blockSize)
        {
            case 32:
                blockBytes = 4;
                x1Size = 13; x2Size = 19;
                x1Taps = new[] { 12, 7, 8, 5, 3 };
                x2Taps = new[] { 18, 7, 12, 10, 8, 3 };
                break;

            case 48:
                blockBytes = 6;
                x1Size = 19; x2Size = 29;
                x1Taps = new[] { 18, 12, 15, 7, 6 };
                x2Taps = new[] { 28, 19, 21, 13, 15, 6 };
                break;

            case 64:
                blockBytes = 8;
                x1Size = 25; x2Size = 39;
                x1Taps = new[] { 24, 15, 20, 11, 9 };
                x2Taps = new[] { 38, 25, 33, 21, 14, 9 };
                break;

            default:
                throw new ArgumentException("Blok boyutu 32 / 48 / 64 olmalı.");
        }

        if (IR.Length < Rounds)
            throw new InvalidOperationException("IR dizisi 254 bitten kısa olamaz.");
    }

    // =========================================================
    // Public API (UI için)
    // =========================================================

    // ÇIKTI FORMAT: "32:" + HEX  (Decrypt otomatik blocksize bulsun diye)
    public string EncryptTextToHex(string plaintext, string key)
    {
        if (plaintext == null) plaintext = "";
        byte[] pt = Encoding.UTF8.GetBytes(plaintext);
        byte[] k10 = KeyTo10Bytes(key);

        // CTR mode + PKCS7 padding (UI'de daha “blok gibi” görünmesi için)
        byte[] padded = Pkcs7Pad(pt, blockBytes);
        byte[] ct = CryptCtr(padded, k10);

        return $"{blockSizeBits}:{BytesToHex(ct)}";
    }

    public string DecryptHexToText(string hexWithOptionalPrefix, string key)
    {
        if (string.IsNullOrWhiteSpace(hexWithOptionalPrefix))
            return "";

        byte[] k10 = KeyTo10Bytes(key);

        // "32:...." / "48:...." / "64:...." prefix varsa ayıkla
        string hex = hexWithOptionalPrefix.Trim();
        int parsedBlock = TryParsePrefixAndGetBlockSize(ref hex);
        if (parsedBlock != 0 && parsedBlock != blockSizeBits)
            throw new InvalidOperationException($"Bu HEX {parsedBlock}-bit ile üretilmiş. UI'da {parsedBlock}-bit seçmelisin.");

        byte[] ct = HexToBytes(hex);

        byte[] paddedPt = CryptCtr(ct, k10);
        byte[] pt = Pkcs7UnpadStrict(paddedPt, blockBytes);

        return Encoding.UTF8.GetString(pt);
    }

    // =========================================================
    // CTR MODE (decrypt = encrypt)
    // =========================================================
    private byte[] CryptCtr(byte[] data, byte[] key10)
    {
        byte[] outb = new byte[data.Length];

        // 80-bit key -> round key bits (2*254 = 508 bit)
        bool[] roundKeys = GenerateRoundKeyBits(key10, Rounds * 2);

        // Counter = 0,1,2...
        ulong counter = 0;
        int offset = 0;

        while (offset < data.Length)
        {
            // counterBlock = blockBytes
            byte[] counterBlock = new byte[blockBytes];

            // big-endian counter write (en basit, deterministik)
            for (int i = 0; i < blockBytes; i++)
            {
                int shift = (blockBytes - 1 - i) * 8;
                counterBlock[i] = (byte)((counter >> shift) & 0xFF);
            }

            // keystream = KATAN_EncryptBlock(counterBlock)
            byte[] ks = EncryptBlock(counterBlock, roundKeys);

            for (int i = 0; i < blockBytes && offset < data.Length; i++)
            {
                outb[offset] = (byte)(data[offset] ^ ks[i]);
                offset++;
            }

            counter++;
        }

        return outb;
    }

    // =========================================================
    // REAL KATAN CORE (ENCRYPT BLOCK)
    // =========================================================
    private byte[] EncryptBlock(byte[] inputBlock, bool[] roundKeys)
    {
        // state bits: MSB-first
        bool[] state = BytesToBitsMSB(inputBlock, blockSizeBits);

        // split
        bool[] L1 = new bool[x1Size];
        bool[] L2 = new bool[x2Size];
        Array.Copy(state, 0, L1, 0, x1Size);
        Array.Copy(state, x1Size, L2, 0, x2Size);

        for (int r = 0; r < Rounds; r++)
        {
            bool ka = roundKeys[2 * r];
            bool kb = roundKeys[2 * r + 1];

            // KATAN feedback functions (spec style)
            // fa = L1[a0] ^ L1[a1] ^ (L1[a2]&L1[a3]) ^ (L1[a4]&ka) ^ IR[r]
            bool fa =
                L1[x1Taps[0]] ^
                L1[x1Taps[1]] ^
                (L1[x1Taps[2]] & L1[x1Taps[3]]) ^
                (L1[x1Taps[4]] & ka) ^
                IR[r];

            // fb = L2[b0] ^ L2[b1] ^ (L2[b2]&L2[b3]) ^ (L2[b4]&L2[b5]) ^ kb
            bool fb =
                L2[x2Taps[0]] ^
                L2[x2Taps[1]] ^
                (L2[x2Taps[2]] & L2[x2Taps[3]]) ^
                (L2[x2Taps[4]] & L2[x2Taps[5]]) ^
                kb;

            bool L1_last = L1[x1Size - 1];
            bool L2_last = L2[x2Size - 1];

            // shift right
            for (int i = x1Size - 1; i > 0; i--) L1[i] = L1[i - 1];
            for (int i = x2Size - 1; i > 0; i--) L2[i] = L2[i - 1];

            // insert
            L1[0] = fa ^ L2_last;
            L2[0] = fb ^ L1_last;
        }

        bool[] outState = new bool[blockSizeBits];
        Array.Copy(L1, 0, outState, 0, x1Size);
        Array.Copy(L2, 0, outState, x1Size, x2Size);

        return BitsToBytesMSB(outState, blockBytes);
    }


    // =========================================================
    // Key Schedule: 80-bit LFSR (standard KATAN/KTANTAN style)
    // newBit = k[0] ^ k[19] ^ k[30] ^ k[67]
    // =========================================================
    private static bool[] GenerateRoundKeyBits(byte[] key10, int nbits)
    {
        bool[] k = new bool[KeyBits];
        // key bits MSB-first
        for (int i = 0; i < KeyBits; i++)
            k[i] = ((key10[i / 8] >> (7 - (i % 8))) & 1) == 1;

        bool[] outBits = new bool[nbits];

        for (int i = 0; i < nbits; i++)
        {
            outBits[i] = k[0];

            bool newBit = k[0] ^ k[19] ^ k[30] ^ k[67];

            // shift
            for (int j = 0; j < KeyBits - 1; j++)
                k[j] = k[j + 1];

            k[KeyBits - 1] = newBit;
        }

        return outBits;
    }

    // =========================================================
    // Helpers
    // =========================================================
    private static byte[] KeyTo10Bytes(string key)
    {
        if (key == null)
            throw new ArgumentException("Anahtar boş olamaz.");

        byte[] k = Encoding.UTF8.GetBytes(key);

        if (k.Length != 10)
            throw new ArgumentException(
                "KATAN anahtarı tam olarak 10 karakter (80 bit) olmalıdır.");

        return k;
    }


    private static bool[] BytesToBitsMSB(byte[] input, int bitCount)
    {
        bool[] bits = new bool[bitCount];
        for (int i = 0; i < bitCount; i++)
            bits[i] = ((input[i / 8] >> (7 - (i % 8))) & 1) == 1;
        return bits;
    }

    private static byte[] BitsToBytesMSB(bool[] bits, int byteCount)
    {
        byte[] outb = new byte[byteCount];
        for (int i = 0; i < bits.Length; i++)
            if (bits[i]) outb[i / 8] |= (byte)(1 << (7 - (i % 8)));
        return outb;
    }

    private static string BytesToHex(byte[] b)
        => BitConverter.ToString(b).Replace("-", "");

    private static byte[] HexToBytes(string hex)
    {
        hex = hex.Replace("0x", "", StringComparison.OrdinalIgnoreCase)
                 .Replace(" ", "").Replace("-", "").Trim();

        if (hex.Length % 2 != 0)
            throw new ArgumentException("HEX uzunluğu çift olmalı.");

        byte[] b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return b;
    }

    private int TryParsePrefixAndGetBlockSize(ref string hex)
    {
        // "32:...."
        if (hex.Length >= 3 && hex[2] == ':')
        {
            string pref = hex.Substring(0, 2);
            if (int.TryParse(pref, out int bs) && (bs == 32 || bs == 48 || bs == 64))
            {
                hex = hex.Substring(3);
                return bs;
            }
        }
        return 0;
    }

    private static byte[] Pkcs7Pad(byte[] data, int blockBytes)
    {
        int pad = blockBytes - (data.Length % blockBytes);
        if (pad == 0) pad = blockBytes;

        byte[] outb = new byte[data.Length + pad];
        Buffer.BlockCopy(data, 0, outb, 0, data.Length);
        for (int i = data.Length; i < outb.Length; i++)
            outb[i] = (byte)pad;

        return outb;
    }

    private static byte[] Pkcs7UnpadStrict(byte[] data, int blockBytes)
    {
        if (data.Length == 0 || data.Length % blockBytes != 0)
            throw new InvalidOperationException("Padding geçersiz. (uzunluk blokla uyumsuz)");

        int pad = data[^1];
        if (pad <= 0 || pad > blockBytes)
            throw new InvalidOperationException("Padding geçersiz. (pad değeri hatalı)");

        for (int i = data.Length - pad; i < data.Length; i++)
            if (data[i] != pad)
                throw new InvalidOperationException("Padding geçersiz. (pad byte'ları uyuşmuyor)");

        byte[] outb = new byte[data.Length - pad];
        Buffer.BlockCopy(data, 0, outb, 0, outb.Length);
        return outb;
    }
}
