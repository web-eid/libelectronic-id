/*
 * Copyright (c) 2020-2022 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "../../src/electronic-ids/pkcs11/PKCS11CardManager.hpp"

#include <openssl/evp.h>

#include <gtest/gtest.h>

using namespace electronic_id;

std::vector<CK_BYTE> base64Decode(const std::string& base64String)
{
    const auto predictedDecodedLength = 3 * base64String.length() / 4; // predict output size

    std::vector<CK_BYTE> decoded(predictedDecodedLength + 1);

    const auto actualDecodedLength =
        EVP_DecodeBlock(reinterpret_cast<unsigned char*>(decoded.data()),
                        reinterpret_cast<const unsigned char*>(base64String.data()),
                        static_cast<int>(base64String.size()));

    if (predictedDecodedLength != static_cast<unsigned long>(actualDecodedLength)) {
        throw std::runtime_error("base64Decode error");
    }

    return decoded;
}

const std::string AUTH_CERT =
    "MIIEAzCCA2WgAwIBAgIQOWkBWXNDJm1byFd3XsWkvjAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0"
    "sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4"
    "MB4XDTE4MTAxODA5NTA0N1oXDTIzMTAxNzIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy"
    "1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UE"
    "BRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR5k1lXzvSeI9O/"
    "1s1pZvjhEW8nItJoG0EBFxmLEY6S7ki1vF2Q3TEDx6dNztI1Xtx96cs8r4zYTwdiQoDg7k3diUuR9nTWGxQEMO1FDo4Y9f"
    "AmiPGWT++GuOVoZQY3XxijggHDMIIBvzAJBgNVHRMEAjAAMA4GA1UdDwEB/"
    "wQEAwIDiDBHBgNVHSAEQDA+"
    "MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAIBgYEAI96AQIwHwYDVR0RBB"
    "gwFoEUMzgwMDEwODU3MThAZWVzdGkuZWUwHQYDVR0OBBYEFOQsvTQJEBVMMSmhyZX5bibYJubAMGEGCCsGAQUFBwEDBFUw"
    "UzBRBgYEAI5GAQUwRzBFFj9odHRwczovL3NrLmVlL2VuL3JlcG9zaXRvcnkvY29uZGl0aW9ucy1mb3ItdXNlLW9mLWNlcn"
    "RpZmljYXRlcy8TAkVOMCAGA1UdJQEB/"
    "wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAfBgNVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+"
    "ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQ"
    "UFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBiwAwgYcCQgH1"
    "UsmMdtLZti51Fq2QR4wUkAwpsnhsBV2HQqUXFYBJ7EXnLCkaXjdZKkHpABfM0QEx7UUhaI4i53jiJ7E1Y7WOAAJBDX4z61"
    "pniHJapI1bkMIiJQ/ti7ha8fdJSMSpAds5CyHIyHkQzWlVy86f9mA7Eu3oRO/1q+eFUzDbNN3Vvy7gQWQ=";

const std::string SIGNING_CERT =
    "MIID7DCCA02gAwIBAgIQOZYpcFbeurZbzz9ngqCZsTAKBggqhkjOPQQDBDBgMQswCQYDVQQGEwJFRTEbMBkGA1UECgwSU0"
    "sgSUQgU29sdXRpb25zIEFTMRcwFQYDVQRhDA5OVFJFRS0xMDc0NzAxMzEbMBkGA1UEAwwSVEVTVCBvZiBFU1RFSUQyMDE4"
    "MB4XDTE4MTAyMzE1MzM1OVoXDTIzMTAyMjIxNTk1OVowfzELMAkGA1UEBhMCRUUxKjAoBgNVBAMMIUrDlUVPUkcsSkFBSy"
    "1LUklTVEpBTiwzODAwMTA4NTcxODEQMA4GA1UEBAwHSsOVRU9SRzEWMBQGA1UEKgwNSkFBSy1LUklTVEpBTjEaMBgGA1UE"
    "BRMRUE5PRUUtMzgwMDEwODU3MTgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASKvaAJSGYBrLcvq0KjgM1sOAS9vbtqeSS2Ok"
    "qyY4i5AazaetYmCtXKOqUUeljOJUGBUzljDFlAEPHs5Fn+vFT7+cGkOVCA93PBYKVsA9avcWyMwgQQJoW6kA4ZN9yD/"
    "mijggGrMIIBpzAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGQDBIBgNVHSAEQTA/"
    "MDIGCysGAQQBg5EhAQIBMCMwIQYIKwYBBQUHAgEWFWh0dHBzOi8vd3d3LnNrLmVlL0NQUzAJBgcEAIvsQAECMB0GA1UdDg"
    "QWBBRYwsjA5GJ7HWPvD8ByThPTZ6j3PDCBigYIKwYBBQUHAQMEfjB8MAgGBgQAjkYBATAIBgYEAI5GAQQwEwYGBACORgEG"
    "MAkGBwQAjkYBBgEwUQYGBACORgEFMEcwRRY/"
    "aHR0cHM6Ly9zay5lZS9lbi9yZXBvc2l0b3J5L2NvbmRpdGlvbnMtZm9yLXVzZS1vZi1jZXJ0aWZpY2F0ZXMvEwJFTjAfBg"
    "NVHSMEGDAWgBTAhJkpxE6fOwI09pnhClYACCk+"
    "ezBzBggrBgEFBQcBAQRnMGUwLAYIKwYBBQUHMAGGIGh0dHA6Ly9haWEuZGVtby5zay5lZS9lc3RlaWQyMDE4MDUGCCsGAQ"
    "UFBzAChilodHRwOi8vYy5zay5lZS9UZXN0X29mX0VTVEVJRDIwMTguZGVyLmNydDAKBggqhkjOPQQDBAOBjAAwgYgCQgDB"
    "TN1LM08SeH18xKQplqAmV8AQhVvrOxRELCmYp54Qr0XTi2i7kMw0k8gVOV84RlPQP6/ayjs4+ytRbIdkBZK1vQJCARF17/"
    "gWYUu7bmy/AXT6fWgyuDV5j2UC2cWDFhPUYyS99rdLGSfP10rP9mPK87Y+4HkfJB/qDyENnJYPa5mUsuFK";

TEST(electronic_id_test, pkcs11TokenHasAuthenticationCert)
{
    PKCS11CardManager::Token token;
    token.cert = base64Decode(AUTH_CERT);
    EXPECT_TRUE(token.certificateType().isAuthentication());
}

TEST(electronic_id_test, pkcs11TokenHasSigningCert)
{
    PKCS11CardManager::Token token;
    token.cert = base64Decode(SIGNING_CERT);
    EXPECT_FALSE(token.certificateType().isAuthentication());
}
