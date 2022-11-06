using MyCryptography;

var tripleDES = new TripleDES();
Console.WriteLine($"Key: {tripleDES.Key}");

var plaintext1 = (ulong)(new Random()).NextInt64();
var ciphertext = tripleDES.Encrypt(plaintext1);
var plaintext2 = tripleDES.Decrypt(ciphertext);

Console.WriteLine($"Plaintext1: {plaintext1}");
Console.WriteLine($"Ciphertext: {ciphertext}");
Console.WriteLine($"Plaintext2: {plaintext2}");
