using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using UnityEngine;

public class AesCbc
{
    const int PASSWORD_LENGTH = 16;
    const int ITERATION_COUNT = 978;

    /// <summary>
    /// 暗号化
    /// </summary>
    /// <param name="bytes">バイト配列</param>
    /// <param name="password">パスワード</param>
    /// <returns>暗号化したバイト配列</returns>
    public static byte[] Encrypt(byte[] bytes, string password)
    {
        byte[] outbytes = null;

        try
        {
            using (AesManaged aes = new AesManaged())
            {
                aes.BlockSize = PASSWORD_LENGTH * 8;
                aes.KeySize   = PASSWORD_LENGTH * 8;
                aes.Mode      = CipherMode.CBC;
                aes.Padding   = PaddingMode.PKCS7;

                var passBytes = GetDeriveBytes(password, aes.BlockSize, aes.KeySize);

                var salt      = passBytes.Salt;
                aes.Key       = passBytes.Key;
                aes.IV        = passBytes.IV;

                byte[] outenc;

                // encrypt
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    outenc = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
                }

                // salt, IV を埋め込む
                outbytes =
                    new byte[
                        outenc.Length +
                        salt.Length +
                        aes.IV.Length
                    ];

                int pos = 0;

                // データの順番
                byte[][] writeBytes = new byte[][]
                {
                    salt,
                    outenc,
                    aes.IV,
                };

                for (int i = 0; i < writeBytes.Length; i++)
                {
                    Buffer.BlockCopy(writeBytes[i], 0, outbytes, pos, writeBytes[i].Length);
                    pos += writeBytes[i].Length;
                }
            }
        }
        catch (Exception ex)
        {
            Debug.LogError(ex.Message);
        }

        return outbytes;
    }

    /// <summary>
    /// 暗号化したバイト配列の複合化
    /// </summary>
    /// <param name="bytes">暗号化したバイト配列</param>
    /// <param name="password">パスワード</param>
    /// <returns>バイト配列</returns>
    public static byte[] Decrypt(byte[] bytes, string password)
    {
        byte[] outbytes = null;

        try
        {
            // decrypt
            byte[] outenc = new byte[bytes.Length - PASSWORD_LENGTH * 2];
            byte[] salt   = new byte[PASSWORD_LENGTH];
            byte[] IV     = new byte[PASSWORD_LENGTH];

            Buffer.BlockCopy(bytes, 0,                              salt,   0, salt.Length);
            Buffer.BlockCopy(bytes, PASSWORD_LENGTH,                outenc, 0, outenc.Length);
            Buffer.BlockCopy(bytes, bytes.Length - PASSWORD_LENGTH, IV,     0, IV.Length);

            using (AesManaged aes = new AesManaged())
            {
                aes.BlockSize = PASSWORD_LENGTH * 8;
                aes.KeySize = PASSWORD_LENGTH * 8;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                Rfc2898DeriveBytes deriveBytes = new Rfc2898DeriveBytes(password, salt);
                deriveBytes.IterationCount     = ITERATION_COUNT;
                byte[] key    = deriveBytes.GetBytes(PASSWORD_LENGTH);
                aes.Key       = key;
                aes.IV        = IV;

                // decrypt
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    outbytes = decryptor.TransformFinalBlock(outenc, 0, outenc.Length);
                }
            }
        }
        catch (Exception ex)
        {
            Debug.LogError(ex.Message);
        }

        return outbytes;
    }

    /// <summary>
    /// ランダムパスワードを生成
    /// </summary>
    /// <param name="password">パスワード</param>
    /// <param name="keySize">キーサイズ (byte * 8)</param>
    /// <param name="blockSize">ブロックサイズ (byte * 8)</param>
    /// <returns></returns>
    public static (byte[] Salt, byte[] Key, byte[] IV) GetDeriveBytes(string password, int keySize, int blockSize)
    {
        Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, PASSWORD_LENGTH);
        rfc2898DeriveBytes.IterationCount     = ITERATION_COUNT;

        var salt = rfc2898DeriveBytes.Salt;
        var key  = rfc2898DeriveBytes.GetBytes(keySize / 8);
        var IV   = rfc2898DeriveBytes.GetBytes(blockSize / 8);

        return (salt, key, IV);
    }
}
