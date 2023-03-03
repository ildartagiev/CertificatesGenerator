using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

Console.Write("Certificate name: ");

string? cn = null;
cn = Console.ReadLine();

if (cn is null)
{
    Console.WriteLine("Сertificate name is not entered.");
    return;
}

Console.WriteLine(cn);

var encryptionCert = CreateCertificate(
    $"CN={cn} Encryption Certificate",
    $"{cn} Encryption Certificate",
    X509KeyUsageFlags.KeyEncipherment);

var signInCert = CreateCertificate(
    $"CN={cn} Signing Certificate",
    $"{cn} Signing Certificate",
    X509KeyUsageFlags.DigitalSignature);

ExportCertificate(encryptionCert, "encryption-certificate.pfx", "certificates");
ExportCertificate(signInCert, "signing-certificate.pfx", "certificates");

static X509Certificate2 CreateCertificate(string distinguishedName, string friendlyName, X509KeyUsageFlags x509KeyUsageFlags)
{
    using var algorithm = RSA.Create(keySizeInBits: 2048);
    var subject = new X500DistinguishedName(distinguishedName);
    var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509KeyUsageExtension(x509KeyUsageFlags, critical: true));

    var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(20));

    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
    {
        certificate.FriendlyName = friendlyName;
    }

    return certificate;
}

static void ExportCertificate(X509Certificate2 certificate, string filename, string path)
{
    if (!Directory.Exists(path))
    {
        Directory.CreateDirectory(path);
    }

    File.WriteAllBytes(Path.Combine(path, filename),
        certificate.Export(X509ContentType.Pfx, string.Empty));
}

Console.WriteLine("Done.");
