using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

var batchBody = "BRBANK;06971135800;PIX;John Smith;j.smith@example.com;1.00;9999;Payout";
var pemKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQCW8dxhuYKAgwfwlNqSit0qxFYNOktxWcRboNopWaia75y8eWEC\nsLqHWpw/gbNbaQzikmI+Hj576RvIvWPDGUHnW8DWnOxliAkd8kYHf1EhVWDzoQCM\nVmRxX8QzmKZtN3DmuctK4qBRCZA9k/1aROJpMBnCkiBBS4Kbyf6/pR1YdQIDAQAB\nAoGAFo9Rc92pDpIG5sMoo8xTX+f2QIXc7rUO7u7sjE+VLorvbw/pGuDVEBPP1IIL\nD3d08IwWWNhmWFivyWHc/jTRL4syyhd0ON2ZjVyaD3gwWOnzlISIcmz5u3iVZbXn\nKHorW4lRWUf6zwyflLDRMi0KDQ9x2ens4iieFIJRcpxsUoUCQQDKhhGY8JcCwdQN\noyS1mixNeGsn56nFWH6+zCGJKDLnCdNCRu9dWb+LRNy2/rUiFYirO9epiiIBeBeH\ncWSgYcU7AkEAvs06GPZjZQrJCif+WsyYSxcsV2i7Hdy1b8jwprEoEA+HYzZnqkgV\nXPsiIIGjRi6l/O/dD/p0jqQqZQ1y6PO+DwJBAMcMFeeXLxSKpHvyyHWkXb6Wh9rk\nmbtYStoDj0JavAzPX09YoJHDT7r1p2hD1or1VynU2xXKqbl/6sA39oqbDVkCQQCO\nfZeIsuCxwec3lXyH9Mk7MtgjgwxSldRN4iOOaTkBHYe/WQ78BQ8nPElVO1ti+01s\n4vkViLZpHEKo6u1I+VaTAkBY1ZkihEiL+4Zv/LIM4wcAewLkADx1Oou6mEDCbF3r\nyZNxhoL3inPPGgGvtVNDgqe8XRiwZc52J8MxWWXDxbii\n-----END RSA PRIVATE KEY-----\n";   

// Send a POST request using a hardcoded hash (dictionary), not command-line arguments.
var data = new Dictionary<string, string>
{
    ["operation"] = "import_batch_advanced",
    ["login"] = "myloginname",
    ["plain_password"] = "myplainpassword",
    ["batch"] = batchBody,
    ["verification_type"] = "SIGNATURE",
};

try
{
    var result = await importBatch(data, batchBody, pemKey);
    Console.WriteLine("Response:\n" + result);
}
catch (Exception ex)
{
    Console.Error.WriteLine("Request failed: " + ex.Message);
}

static async Task<string> importBatch(Dictionary<string, string> data, string batchBody, string pemPrivateKeyPem)
{
    if (data == null) throw new ArgumentNullException(nameof(data));
    if (batchBody == null) throw new ArgumentNullException(nameof(batchBody));
    if (string.IsNullOrWhiteSpace(pemPrivateKeyPem)) throw new ArgumentException("PEM private key is required", nameof(pemPrivateKeyPem));

    // Compute RSA signature over the batchBody using SHA-1 + PKCS#1 v1.5 to match PHP example
    var signatureBase64 = SignPlaintext(batchBody, pemPrivateKeyPem);
    data["verification_data"] = signatureBase64;

    // Send the request using form-url-encoded content
    return await ApiClient.PostHashAsync(data, useMultipart: false);
}

static string SignPlaintext(string plaintext, string pemPrivateKeyPem)
{
    if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));
    if (string.IsNullOrWhiteSpace(pemPrivateKeyPem)) throw new ArgumentException("PEM private key is required", nameof(pemPrivateKeyPem));

    using RSA rsa = RSA.Create();
    rsa.ImportFromPem(pemPrivateKeyPem.AsSpan());
    byte[] payload = Encoding.UTF8.GetBytes(plaintext);

    // phpseclib RSA::SIGNATURE_PKCS1 without explicit setHash defaults to SHA-1
    // so we mirror that here with SHA1 + PKCS#1 v1.5 and return base64-encoded signature
    byte[] signatureBytes = rsa.SignData(payload, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
    return Convert.ToBase64String(signatureBytes);
}

static class ApiClient
{
    private static readonly HttpClient http = new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    /// <summary>
    /// Sends a hash (dictionary) of data via HTTP POST to https://beta.volan.dev/api/post
    /// Adds header: x-response-type: json
    /// Content-Type can be application/x-www-form-urlencoded (default) or multipart/form-data when useMultipart=true
    /// </summary>
    /// <param name="data">Key-value pairs to send</param>
    /// <param name="useMultipart">If true, uses multipart/form-data; otherwise application/x-www-form-urlencoded</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Response body as string</returns>
    public static async Task<string> PostHashAsync(Dictionary<string, string> data, bool useMultipart = false, CancellationToken cancellationToken = default)
    {
        var url = "https://api.capitalist.net";

        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        // Required custom header
        request.Headers.TryAddWithoutValidation("x-response-format", "json");

        HttpContent content;
        if (!useMultipart)
        {
            content = new FormUrlEncodedContent(data ?? new Dictionary<string, string>());
        }
        else
        {
            var multipart = new MultipartFormDataContent();
            if (data != null)
            {
                foreach (var kv in data)
                {
                    multipart.Add(new StringContent(kv.Value ?? string.Empty, Encoding.UTF8), kv.Key);
                }
            }
            content = multipart;
        }

        request.Content = content;

        using var response = await http.SendAsync(request, cancellationToken);
        var responseText = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return responseText;
    }
}
