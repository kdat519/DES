using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyCryptography
{
    public struct Block
    {
        public ulong Data { get; init; }
        public int Size { get; init; }

        public Block(ulong data, int size)
        {
            Debug.Assert(1 <= size && size <= 64);
            Size = size;
            if (size == 64) Data = data;
            else Data = ~(~0UL << size) & data;
        }
        public override string ToString()
        {
            return Convert.ToString((long)Data, toBase: 2).PadLeft(Size, '0');
        }
        // Chia block thành các block nhỏ hơn (chunk)
        public static List<Block> Split(Block block, int chunkSize)
        {
            Debug.Assert(0 < chunkSize && chunkSize <= block.Size);
            Debug.Assert(block.Size % chunkSize == 0);
            List<Block> result = new List<Block>();
            for (int i = block.Size - chunkSize; i >= 0; i -= chunkSize)
            {
                Block chunk = new Block((block.Data >> i), chunkSize);
                result.Add(chunk);
            }
            return result;
        }
        // Gộp các block (chunk) thành một block lớn hơn
        public static Block Join(List<Block> chunks)
        {
            ulong data = 0UL;
            int size = 0;
            foreach (Block chunk in chunks)
            {
                data <<= chunk.Size;
                data |= chunk.Data;
                size += chunk.Size;
            }
            return new Block(data, size);
        }
        // Hoán vị block theo bản, bảng tính chỉ số từ 1
        public static Block Permute(Block block, int[] table)
        {
            ulong data = 0UL;
            foreach (var position in table)
            {
                var index = position - 1;
                Debug.Assert(0 <= index && index < block.Size);
                data <<= 1;
                if ((block.Data & 1UL << index) != 0)
                    data |= 1UL;
            }
            return new Block(data, table.Length);
        }
        // Dịch vòng
        public static Block RotateLeft(Block block, int count)
        {
            Debug.Assert(0 < count && count < block.Size);
            ulong data = block.Data << count | block.Data >> (block.Size - count);
            return new Block(data, block.Size);
        }
        // Xor 2 block
        public static Block Xor(Block block1, Block block2)
        {
            Debug.Assert(block1.Size == block2.Size);
            return new Block(block1.Data ^ block2.Data, block1.Size);
        }
    }
}
