using System.Collections.Generic;
using System.IO;
using System.Text;
using UnityEngine;
using UnityEngine.UI;

/// <summary>
/// Exsample
/// </summary>
[System.Serializable]
public class SubEntity
{
    public string Name;
    public string Data;
}

[System.Serializable]
public class RowEntity
{
    public string          GUID;
    public string          Title;
    public string          Url;
    public string          Memo;
    public List<SubEntity> Subs;
}


public class Sample : MonoBehaviour
{
    [SerializeField]
    Button      Encrypt;
    [SerializeField]
    Button      Decrypt;

    const string APP_PASSWORD = "01234567";

    void Awake()
    {
        Encrypt.onClick.AddListener(clickEncrypt);
        Decrypt.onClick.AddListener(clickDecrypt);

        Directory.CreateDirectory("Results");
    }

    void clickEncrypt()
    {
        RowEntity row = new RowEntity();

        // exsample data
        row.GUID = "19fecfe7-0770-41f6-9872-ab7395381979";
        row.Title = "a8";
        row.Url = "http://xxx.a8.net/";
        row.Memo = "ID: 99999999\nhttp://www.a8.net/a8v2/asReminderAction.do";

        row.Subs = new List<SubEntity>();
        row.Subs.Add(new SubEntity() {Name = "ID", Data = "xxxxx"} );
        row.Subs.Add(new SubEntity() {Name = "pass", Data = "aksesa\\\"#ed0w"} );

        // 1. Class Instance -> Json
        string json   = JsonUtility.ToJson(row, true);
        File.WriteAllText("Results/1a_json.txt", json);

        // 2. Json -> Binary
        byte[] bin    = Encoding.ASCII.GetBytes(json);
        File.WriteAllBytes("Results/2a_binary.bin", bin);

        // 3. Encrypt
        byte[] encbin = AesCbc.Encrypt(bin, APP_PASSWORD);
        File.WriteAllBytes("Results/final_encrypt.bin", encbin);

        Debug.Log($"encrypt data: Results/final_encrypt.bin");
    }

    void clickDecrypt()
    {
        // read encrypt file
        byte[] encbin = File.ReadAllBytes("Results/final_encrypt.bin");

        // 1. Decrypt
        byte[] decbin = AesCbc.Decrypt(encbin, APP_PASSWORD);
        File.WriteAllBytes("Results/2b_binary.bin", decbin);

        // 2. Binary -> Json
        string json   = Encoding.ASCII.GetString(decbin);
        File.WriteAllText("Results/1b_json.txt", json);

        // 3. Json -> Class Instance
        var row = JsonUtility.FromJson<RowEntity>(json);
        Debug.Log($"decrypt GUID: {row.GUID}");
    }

}
