using System.Security.Cryptography;
using CistaNAS.Client.Crypto;

// Poly1305のデバッグ用テスト
byte[] key = new byte[32];
byte[] nonce = new byte[12];
key.AsSpan().Fill(0x00);
nonce.AsSpan().Fill(0x00);

// テストデータ: 16バイト（1ブロック）
byte[] plaintext1 = new byte[16];
plaintext1.AsSpan().Fill(0x00);

var (nonce1, cipher1, tag1) = ChaCha20Poly1305.Encrypt(plaintext1, key, nonce);
Console.WriteLine($"16バイトメッセージのタグ: {Convert.ToHexString(tag1)}");

// テストデータ: 1バイト（部分ブロック）
byte[] plaintext2 = new byte[1];
plaintext2.AsSpan().Fill(0x00);

var (nonce2, cipher2, tag2) = ChaCha20Poly1305.Encrypt(plaintext2, key, nonce);
Console.WriteLine($"1バイトメッセージのタグ: {Convert.ToHexString(tag2)}");

// 改ざんテスト
byte[] plaintext3 = new byte[100];
new Random(42).NextBytes(plaintext3);

var (nonce3, cipher3, tag3) = ChaCha20Poly1305.Encrypt(plaintext3, key, nonce);
Console.WriteLine($"100バイトメッセージのタグ: {Convert.ToHexString(tag3)}");

// 暗号文を改ざん
byte[] tamperedCipher = (byte[])cipher3.Clone();
tamperedCipher[0] ^= 0xFF;

try {
    byte[] decrypted = ChaCha20Poly1305.Decrypt(tamperedCipher, tag3, nonce3, key);
    Console.WriteLine("エラー: 改ざん検出されず！");
} catch (CryptographicException) {
    Console.WriteLine("成功: 改ざん検出されました");
}
