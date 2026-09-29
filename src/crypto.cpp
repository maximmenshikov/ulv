#include "stdafx.h"
#include "Precompiled.h"
#pragma comment(lib, "bcrypt.lib")
#include "bcrypt.h"
#include "Precompiled.h"

using namespace Kerr;
#define NT_VERIFY(a)

typedef struct
{
    DWORD size;
    LPVOID data;
} UDATA_BLOB;

/**
 * Copy a Kerr Buffer into a newly allocated blob.
 *
 * @param buffer    Source buffer.
 *
 * @return A new blob holding a copy of the buffer data.
 */
UDATA_BLOB *
BufferToBlob(Buffer &buffer)
{
    UDATA_BLOB *blob = new UDATA_BLOB;

    blob->size = buffer.GetSize();
    blob->data = new char[blob->size];
    memcpy(blob->data, buffer.GetData(), blob->size);
    return blob;
}

/**
 * Free a blob and its data.
 *
 * @param blob    Blob to free.
 */
void
DeleteBlob(UDATA_BLOB *blob)
{
    if (blob->data)
        delete[] blob->data;
    delete blob;
}

#ifdef SIGNER_MODE

/**
 * Generate an ECDSA key pair and export the public key and the key pair as blobs.
 *
 * @param algorithmProvider    Opened ECDSA algorithm provider.
 * @param pubKey               Receives the exported public-key blob.
 * @param privKeyPair          Receives the exported key-pair blob.
 */
void
GenerateKeys(AlgorithmProvider &algorithmProvider, UDATA_BLOB **pubKey,
             UDATA_BLOB **privKeyPair)
{
    Buffer publicKeyBlob;
    Buffer keyPairBlob;
    {
        //
        // Generate a new key pair.
        //

        Key key;
        const ULONG keySize = 256;

        NT_VERIFY(key.GenerateKeyPair(algorithmProvider, keySize,
                                      0)); // flags

        NT_VERIFY(key.FinalizeKeyPair(0)); // flags

        //
        // Export the public key.
        //

        ULONG publicKeyBlobSize = 0;

        NT_VERIFY(key.ExportKey(0, // reserved
                                BCRYPT_ECCPUBLIC_BLOB,
                                0, // output
                                0, // output size
                                publicKeyBlobSize,
                                0)); // flags

        NT_VERIFY(publicKeyBlob.Create(publicKeyBlobSize));

        NT_VERIFY(key.ExportKey(0, // reserved
                                BCRYPT_ECCPUBLIC_BLOB, publicKeyBlob.GetData(),
                                publicKeyBlob.GetSize(), publicKeyBlobSize,
                                0)); // flags

        //
        // Export the key pair.
        //

        ULONG keyPairBlobSize = 0;

        NT_VERIFY(key.ExportKey(0, // reserved
                                BCRYPT_ECCPRIVATE_BLOB,
                                0, // output
                                0, // output size
                                keyPairBlobSize,
                                0)); // flags

        NT_VERIFY(keyPairBlob.Create(keyPairBlobSize));

        NT_VERIFY(key.ExportKey(0, // reserved
                                BCRYPT_ECCPRIVATE_BLOB, keyPairBlob.GetData(),
                                keyPairBlob.GetSize(), keyPairBlobSize,
                                0)); // flags

        *pubKey = BufferToBlob(publicKeyBlob);
        *privKeyPair = BufferToBlob(keyPairBlob);
    }
}

#endif

/**
 * Compute the MD5 hash of a file's contents.
 *
 * @param szFilePath    Path of the file to hash.
 *
 * @return A blob holding the hash, or NULL on error.
 */
UDATA_BLOB *
CreateFileHash(LPWSTR szFilePath)
{
    Buffer hashValue;
    FILE *f = _wfopen(szFilePath, L"rb");
    if (f == NULL)
        return NULL;
    fseek(f, 0L, SEEK_END);
    int fSize = ftell(f);
    fseek(f, 0L, SEEK_SET);
    char *buf = new char[fSize];
    fread(buf, 1, fSize, f);
    fclose(f);

    AlgorithmProvider algorithmProvider;

    if (STATUS_SUCCESS != algorithmProvider.Open(BCRYPT_MD5_ALGORITHM, 0, 0))
        return NULL;

    Hash hash;

    if (STATUS_SUCCESS != hash.Create(algorithmProvider,
                                      0, // secret
                                      0, // secret size
                                      0))
        return NULL;

    if (STATUS_SUCCESS != hash.HashData(buf, fSize, 0))
        return NULL;

    ULONG hashValueSize = 0;
    if (STATUS_SUCCESS != hash.GetHashSize(hashValueSize))
        return NULL;

    if (STATUS_SUCCESS != hashValue.Create(hashValueSize))
        return NULL;

    if (STATUS_SUCCESS !=
        hash.FinishHash(hashValue.GetData(), hashValue.GetSize(), 0))
        return NULL;

    return BufferToBlob(hashValue);
}

#ifdef SIGNER_MODE

/**
 * Sign a hash value with an ECDSA private key.
 *
 * @param algorithmProvider    Opened ECDSA algorithm provider.
 * @param keyPair              Private key-pair blob.
 * @param hashValue            Hash to sign.
 *
 * @return A blob holding the signature.
 */
UDATA_BLOB *
Sign(AlgorithmProvider *algorithmProvider, UDATA_BLOB *keyPair,
     UDATA_BLOB *hashValue)
{
    NTSTATUS stat = 0;
    //
    // Sign the hash value with the private key.
    //

    Buffer signature;
    {
        Key key;

        stat = key.ImportKeyPair(*algorithmProvider,
                                 0, // reserved
                                 BCRYPT_ECCPRIVATE_BLOB, keyPair->data,
                                 keyPair->size,
                                 0); // flags

        ULONG signatureSize = 0;

        stat = key.SignHash(0, // padding info
                            hashValue->data, hashValue->size,
                            0, // output
                            0, // output size
                            signatureSize,
                            0); // flags;

        stat = signature.Create(signatureSize);

        stat =
            key.SignHash(0, // padding info
                         hashValue->data, hashValue->size, signature.GetData(),
                         signature.GetSize(), signatureSize,
                         0); // flags;
        return BufferToBlob(signature);
    }
}

#endif

/**
 * Verify an ECDSA signature over a hash with a public key.
 *
 * @param algorithmProvider    Opened ECDSA algorithm provider.
 * @param hashValue            Hashed data that was signed.
 * @param signature            Signature to verify.
 * @param pubKey               Public-key blob.
 *
 * @return TRUE if the signature is valid, FALSE otherwise.
 */
BOOL
Verify(AlgorithmProvider *algorithmProvider, UDATA_BLOB *hashValue,
       UDATA_BLOB *signature, UDATA_BLOB *pubKey)
{
    Key key;
    key.ImportKeyPair(*algorithmProvider,
                      0, // reserved
                      BCRYPT_ECCPUBLIC_BLOB, pubKey->data, pubKey->size,
                      0); // flags

    NTSTATUS status = key.VerifySignature(0, // padding info
                                          hashValue->data, hashValue->size,
                                          signature->data, signature->size,
                                          0); // flags

    if (status == STATUS_SUCCESS)
        return TRUE;
    return FALSE;
}

/**
 * Write a blob to a file.
 *
 * @param szFileName    Destination file path.
 * @param blob          Blob to write.
 */
void
SaveBlob(LPWSTR szFileName, UDATA_BLOB *blob)
{
    FILE *f = _wfopen(szFileName, L"wb");
    fwrite(blob->data, 1, blob->size, f);
    fclose(f);
}

/**
 * Read a file into a newly allocated blob.
 *
 * @param szFileName    Source file path.
 *
 * @return A new blob holding the file contents, or NULL on error.
 */
UDATA_BLOB *
LoadBlob(LPWSTR szFileName)
{
    FILE *f = _wfopen(szFileName, L"rb");
    if (f)
    {
        UDATA_BLOB *blob = new UDATA_BLOB;
        fseek(f, 0L, SEEK_END);
        int fSize = ftell(f);
        fseek(f, 0L, SEEK_SET);
        blob->size = fSize;
        blob->data = new char[fSize];
        fread(blob->data, 1, blob->size, f);
        fclose(f);
        return blob;
    }
    return NULL;
}

/**
 * Verify a file against a detached signature using ECDSA-P256.
 *
 * @param szFileName    Path of the file to verify.
 * @param pubKey        Public-key blob.
 * @param signature     Detached signature blob.
 *
 * @return TRUE if the signature is valid, FALSE otherwise.
 */
BOOL
VerifyFile(LPWSTR szFileName, UDATA_BLOB *pubKey, UDATA_BLOB *signature)
{
    BOOL result = FALSE;
    AlgorithmProvider algorithmProvider;

    if (algorithmProvider.Open(BCRYPT_ECDSA_P256_ALGORITHM, 0, 0) !=
        STATUS_SUCCESS)
    {
        return FALSE;
    }

    UDATA_BLOB *hashValue = CreateFileHash(szFileName);
    if (hashValue == NULL)
        return FALSE;

    result = Verify(&algorithmProvider, hashValue, signature, pubKey);

    algorithmProvider.Close(0);

    return result;
}

#ifdef SIGNER_MODE

/**
 * Hash a file and sign it with an ECDSA-P256 private key.
 *
 * @param szFileName     Path of the file to sign.
 * @param privKeyPair    Private key-pair blob.
 *
 * @return A blob holding the signature, or NULL on error.
 */
UDATA_BLOB *
SignFile(LPWSTR szFileName, UDATA_BLOB *privKeyPair)
{
    BOOL result = FALSE;
    AlgorithmProvider algorithmProvider;

    if (algorithmProvider.Open(BCRYPT_ECDSA_P256_ALGORITHM, 0, 0) !=
        STATUS_SUCCESS)
    {
        return NULL;
    }
    UDATA_BLOB *hashValue = CreateFileHash(szFileName);
    if (hashValue == NULL)
        return NULL;
    UDATA_BLOB *signature = Sign(&algorithmProvider, privKeyPair, hashValue);

    algorithmProvider.Close(0);

    return signature;
}

#endif

/**
 * Verify a file against its detached "<name>s" signature file.
 *
 * @param szFileName    Path of the file to verify.
 * @param pubKey        Public-key blob.
 *
 * @return TRUE if the signature is valid, FALSE otherwise.
 */
BOOL
PLVerifyFile(LPWSTR szFileName, UDATA_BLOB *pubKey)
{
    BOOL result = FALSE;

    if (szFileName == NULL || pubKey == NULL || wcslen(szFileName) == 0)
        return FALSE;

    wchar_t *signFileName = new wchar_t[wcslen(szFileName) + 1 + 1];
    if (signFileName)
    {
        wcscpy(signFileName, szFileName);
        wcscat(signFileName, L"s");

        UDATA_BLOB *signature = LoadBlob(signFileName);
        if (signature == NULL)
        {
            delete[] signFileName;
            return FALSE;
        }

        result = VerifyFile(szFileName, pubKey, signature);
        if (signature)
            DeleteBlob(signature);
        delete[] signFileName;
    }
    return result;
}

unsigned char ultraPublicKey[72] = {
    0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00, 0x75, 0xF5, 0x8B, 0x27,
    0x81, 0x3D, 0x82, 0x35, 0xA3, 0x0F, 0x44, 0x9F, 0x97, 0x3A, 0xE5, 0xAF,
    0xEF, 0x87, 0x2F, 0x1E, 0x98, 0x31, 0xC7, 0x1D, 0x2E, 0x8A, 0x3A, 0x3F,
    0x8C, 0x39, 0xF4, 0xC3, 0xFA, 0xCD, 0x05, 0xCA, 0x72, 0x4F, 0x71, 0x5A,
    0x16, 0xCD, 0xBA, 0x94, 0x84, 0x59, 0x67, 0xFA, 0x6B, 0x49, 0x46, 0x39,
    0xC1, 0x02, 0x14, 0x77, 0xCE, 0x7D, 0x5B, 0xB7, 0xDD, 0x1C, 0xC1, 0xF8};

/**
 * Wrap an existing buffer in a blob without copying it.
 *
 * @param data    Buffer to wrap.
 * @param size    Size of the buffer, in bytes.
 *
 * @return A new blob referencing the buffer, or NULL on error.
 */
UDATA_BLOB *
LoadBlob(unsigned char *data, int size)
{
    UDATA_BLOB *blob = new UDATA_BLOB;
    if (blob)
    {
        blob->size = size;
        blob->data = data;
        return blob;
    }
    return NULL;
}

UDATA_BLOB *ultraPublicKeyBlob = NULL;

/**
 * Verify every DLL in a directory against the built-in ultra public key.
 *
 * @param path    Directory path, including a trailing separator.
 *
 * @return TRUE if all DLLs verify, FALSE if any fails.
 */
BOOL
PLVerifySignatures(wchar_t *path)
{
    if (path == NULL)
        return FALSE;
    BOOL result = FALSE;

    if (ultraPublicKeyBlob == NULL)
        ultraPublicKeyBlob = LoadBlob(ultraPublicKey, sizeof(ultraPublicKey));
    if (ultraPublicKeyBlob)
    {
        wchar_t *ffPath = new wchar_t[wcslen(path) + 2 + 1];
        wcscpy(ffPath, path);
        wcscat(ffPath, L"*");
        WIN32_FIND_DATAW fd;
        HANDLE Hf = FindFirstFileW(ffPath, &fd);
        delete[] ffPath;
        if (Hf != INVALID_HANDLE_VALUE)
        {
            do
            {
                // skip '.' and '..'
                if (fd.cFileName[0] == L'.')
                    if ((fd.cFileName[1] == L'.' && fd.cFileName[2] == L'\0') ||
                        fd.cFileName[1] == L'\0')
                        continue;
                if (wcslen(fd.cFileName) > 3)
                {
                    wchar_t *ext = wcsrchr(fd.cFileName, L'.');
                    if (ext)
                    {
                        ext++;
                        if (wcsicmp(ext, L"dll") == 0)
                        {
                            wchar_t fullPath[1000];
                            wcscpy(fullPath, path);
                            wcscat(fullPath, fd.cFileName);
                            result = PLVerifyFile(fullPath, ultraPublicKeyBlob);
                            if (result == FALSE)
                                break;
                        }
                    }
                }
            } while (FindNextFileW(Hf, &fd));
            FindClose(Hf);
        }
    }
    return result;
}