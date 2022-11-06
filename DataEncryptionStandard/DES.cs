using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyCryptography
{
    public class DES
    {
        public ulong Key { get; }
        List<Block> EncryptSubkeys { get; }
        List<Block> DecryptSubkeys { get; }

        public DES() : this(GetRandomKey()) {}
        public DES(ulong key)
        {
            Key = key;
            var subkeys = GetSubkeys(new Block(key, 64));
            EncryptSubkeys = new List<Block>(subkeys);
            subkeys.Reverse();
            DecryptSubkeys = subkeys;
        }
        // Sinh khóa ngẫu nhiêu, kiểm tra các khóa yếu
        // Không kiểm tra tính chẵn lẻ của các bit mà chỉ bỏ đi
        public static ulong GetRandomKey()
        {
            var random = new Random();
            while (true)
            {
                ulong data = (ulong)random.NextInt64();
                if (!DESTable.WeakKeys.Contains(data))
                {
                    return data;
                }
            }
        }
        // Tạo 16 khóa con
        public static List<Block> GetSubkeys(Block key)
        {
            Debug.Assert(key.Size == 64);
            Block key56 = Block.Permute(key, DESTable.PermutedChoice1);
            Debug.Assert(key56.Size == 56);

            var pair = Block.Split(key56, 28);
            Debug.Assert(pair.Count == 2);

            List<Block> subkeys = new List<Block>();
            for (int i = 0; i <= 15; i++)
            {
                pair[0] = Block.RotateLeft(pair[0], DESTable.BitsRotationTable[i]);
                pair[1] = Block.RotateLeft(pair[1], DESTable.BitsRotationTable[i]);
                var shifted = Block.Join(pair);
                var subkey48 = Block.Permute(shifted, DESTable.PermutedChoice2);
                Debug.Assert(subkey48.Size == 48);
                subkeys.Add(subkey48);
            }
            return subkeys;
        }
        // Mã hóa 
        public ulong Encrypt(ulong plaintext)
        {
            return Encrypt(plaintext, EncryptSubkeys);
        }
        // Bỏ bước hoán vị đầu tiên và cuối cùng vì không có ý nghĩa bảo mật
        public static ulong Encrypt(ulong plaintext, List<Block> encryptSubkeys)
        {
            var block = new Block(plaintext, 64);
            var pair = Block.Split(block, 32);
            var (left, right) = (pair[0], pair[1]);
            for (var round = 0; round < 16; round++)
            {
                var bits = FeistelFunction(right, encryptSubkeys[round]);
                (left, right) = (right, Block.Xor(bits, left));
            }
            return Block.Join(new List<Block> { right, left }).Data;
        }
        public static Block FeistelFunction(Block data, Block subkey)
        {
            Debug.Assert(data.Size == 32);
            var data48 = Block.Permute(data, DESTable.ExpansionPermutation);
            data48 = Block.Xor(data48, subkey);
            var list = Block.Split(data48, 6);

            var results = new List<Block>();
            for (var i = 0; i < 8; i++)
            {
                results.Add(new Block(DESTable.SubstitutionBoxes[i][list[i].Data], 4));
            }
            return Block.Permute(Block.Join(results), DESTable.Permutation);
        }
        // Giải mã sử dụng cùng thuật toàn với mã hóa
        public ulong Decrypt(ulong ciphertext)
        {
            return Encrypt(ciphertext, DecryptSubkeys);
        }
        public static ulong Decrypt(ulong ciphertext, List<Block> decryptSubkeys)
        {
            return Encrypt(ciphertext, decryptSubkeys);
        }
    }
    public class TripleDES
    {
        public (ulong, ulong, ulong) Key;
        DES des1, des2, des3;

        public TripleDES() : this(GetRandomKey()) {}
        public TripleDES((ulong, ulong , ulong) key)
        {
            des1 = new DES(key.Item1);
            des2 = new DES(key.Item2);
            des3 = new DES(key.Item3);
            Key = key;
        }
        public static (ulong, ulong, ulong) GetRandomKey()
        {
            return (DES.GetRandomKey(), DES.GetRandomKey(), DES.GetRandomKey());
        }
        public ulong Encrypt(ulong plaintext)
        {
            return des3.Encrypt(des2.Encrypt(des1.Encrypt(plaintext)));
        }
        public ulong Decrypt(ulong ciphertext)
        {
            return des1.Decrypt(des2.Decrypt(des3.Decrypt(ciphertext)));
        }
    }
}
