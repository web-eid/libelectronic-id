/*
 * Copyright (c) 2020-2024 Estonian Information System Authority
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

#pragma once

#include "pcsc-mock/pcsc-mock.hpp"

const PcscMock::ApduScript FINEID_V4_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE {
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0C, 0xa0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4b, 0x43, 0x53, 0x2d,
      0x31, 0x35},
     {0x90, 0x00}},
    // Select authentication certificate file.
    {{0x00, 0xA4, 0x08, 0x04, 0x02, 0x43, 0x31, 0x00},
     {0x62, 0x04, 0x81, 0x02, 0x04, 0x3f, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0x00},
     {0x30, 0x82, 0x04, 0x3b, 0x30, 0x82, 0x03, 0xbf, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04,
      0x06, 0x1c, 0x09, 0x65, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
      0x03, 0x05, 0x00, 0x30, 0x78, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
      0x02, 0x46, 0x49, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x20, 0x44,
      0x69, 0x67, 0x69, 0x2d, 0x20, 0x6a, 0x61, 0x20, 0x76, 0x61, 0x65, 0x73, 0x74, 0x6f, 0x74,
      0x69, 0x65, 0x74, 0x6f, 0x76, 0x69, 0x72, 0x61, 0x73, 0x74, 0x6f, 0x20, 0x54, 0x45, 0x53,
      0x54, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0f, 0x54, 0x65, 0x73,
      0x74, 0x69, 0x76, 0x61, 0x72, 0x6d, 0x65, 0x6e, 0x74, 0x65, 0x65, 0x74, 0x31, 0x24, 0x30,
      0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1b, 0x44, 0x56, 0x56, 0x20, 0x54, 0x45, 0x53,
      0x54, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x20,
      0x2d, 0x20, 0x47, 0x35, 0x45, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x31, 0x32, 0x35,
      0x32, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x38, 0x30, 0x31, 0x32, 0x33,
      0x32, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0x00},
     {0x31, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x79, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
      0x04, 0x06, 0x13, 0x02, 0x46, 0x49, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x05,
      0x13, 0x09, 0x39, 0x39, 0x39, 0x30, 0x32, 0x30, 0x33, 0x38, 0x43, 0x31, 0x0f, 0x30, 0x0d,
      0x06, 0x03, 0x55, 0x04, 0x2a, 0x0c, 0x06, 0x50, 0x48, 0x49, 0x4c, 0x49, 0x50, 0x31, 0x19,
      0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x04, 0x0c, 0x10, 0x53, 0x50, 0x45, 0x43, 0x49, 0x4d,
      0x45, 0x4e, 0x2d, 0x41, 0x55, 0x56, 0x49, 0x4e, 0x45, 0x4e, 0x31, 0x2a, 0x30, 0x28, 0x06,
      0x03, 0x55, 0x04, 0x03, 0x0c, 0x21, 0x53, 0x50, 0x45, 0x43, 0x49, 0x4d, 0x45, 0x4e, 0x2d,
      0x41, 0x55, 0x56, 0x49, 0x4e, 0x45, 0x4e, 0x20, 0x50, 0x48, 0x49, 0x4c, 0x49, 0x50, 0x20,
      0x39, 0x39, 0x39, 0x30, 0x32, 0x30, 0x33, 0x38, 0x43, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07,
      0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03,
      0x62, 0x00, 0x04, 0xf6, 0x57, 0xa9, 0xcf, 0x80, 0xc9, 0x32, 0x26, 0xe1, 0xb1, 0x26, 0xbf,
      0xef, 0x2f, 0x61, 0x6e, 0x65, 0xa9, 0xfb, 0x44, 0x92, 0x8e, 0x43, 0x83, 0x65, 0xb5, 0xfa,
      0x69, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0x00},
     {0x3f, 0x28, 0x4a, 0x6c, 0xc4, 0xb5, 0x26, 0x8e, 0x1a, 0xec, 0x2c, 0x52, 0x63, 0x97, 0x55,
      0x35, 0x82, 0xed, 0x2f, 0x66, 0x12, 0xb7, 0x27, 0xfa, 0x29, 0xc5, 0x7a, 0xf4, 0x4a, 0x55,
      0x6e, 0x31, 0x12, 0xd9, 0xc9, 0x5a, 0x76, 0x8a, 0x30, 0xe3, 0x0f, 0xc2, 0x9e, 0xa9, 0x66,
      0x40, 0xe0, 0xa2, 0x32, 0x09, 0x73, 0xb9, 0xf0, 0x91, 0xa5, 0xec, 0x11, 0xc1, 0xa8, 0xfe,
      0xad, 0xf2, 0x6c, 0xa3, 0x37, 0x54, 0xa0, 0xe6, 0xa3, 0x82, 0x02, 0x15, 0x30, 0x82, 0x02,
      0x11, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x12,
      0x9e, 0xb7, 0xe2, 0x28, 0xc7, 0xf3, 0x94, 0x6a, 0x8b, 0xbd, 0x4d, 0xc6, 0xf4, 0xc2, 0x36,
      0x97, 0x52, 0x42, 0x08, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
      0xa2, 0x83, 0xf0, 0x20, 0x41, 0xf5, 0xbd, 0x6d, 0x78, 0x6b, 0x17, 0x9d, 0x08, 0x41, 0xde,
      0x03, 0x05, 0x8c, 0x4e, 0xb3, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
      0x04, 0x04, 0x03, 0x02, 0x03, 0x88, 0x30, 0x81, 0xcd, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
      0x81, 0xc5, 0x30, 0x81, 0xc2, 0x30, 0x81, 0xbf, 0x06, 0x0a, 0x2a, 0x81, 0x76, 0x84, 0x05,
      0x63, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0x00},
     {0x0a, 0x82, 0x60, 0x01, 0x30, 0x81, 0xb0, 0x30, 0x27, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
      0x05, 0x07, 0x02, 0x01, 0x16, 0x1b, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
      0x77, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x70, 0x73,
      0x39, 0x39, 0x2f, 0x30, 0x81, 0x84, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02,
      0x02, 0x30, 0x78, 0x1a, 0x76, 0x56, 0x61, 0x72, 0x6d, 0x65, 0x6e, 0x6e, 0x65, 0x70, 0x6f,
      0x6c, 0x69, 0x74, 0x69, 0x69, 0x6b, 0x6b, 0x61, 0x20, 0x6f, 0x6e, 0x20, 0x73, 0x61, 0x61,
      0x74, 0x61, 0x76, 0x69, 0x6c, 0x6c, 0x61, 0x20, 0x2d, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
      0x66, 0x69, 0x6b, 0x61, 0x74, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x20, 0x66, 0x69, 0x6e,
      0x6e, 0x73, 0x20, 0x2d, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
      0x65, 0x20, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x20, 0x69, 0x73, 0x20, 0x61, 0x76, 0x61,
      0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77,
      0x77, 0x77, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x70,
      0x73, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0x00},
     {0x39, 0x39, 0x30, 0x30, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x29, 0x30, 0x27, 0x81, 0x25,
      0x53, 0x31, 0x50, 0x68, 0x69, 0x6c, 0x69, 0x70, 0x30, 0x38, 0x37, 0x2e, 0x53, 0x50, 0x45,
      0x43, 0x49, 0x4d, 0x45, 0x4e, 0x2d, 0x41, 0x75, 0x76, 0x69, 0x6e, 0x65, 0x6e, 0x40, 0x74,
      0x65, 0x73, 0x74, 0x69, 0x2e, 0x66, 0x69, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
      0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00, 0x30, 0x38, 0x06, 0x03, 0x55, 0x1d,
      0x1f, 0x04, 0x31, 0x30, 0x2f, 0x30, 0x2d, 0xa0, 0x2b, 0xa0, 0x29, 0x86, 0x27, 0x68, 0x74,
      0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x66, 0x69, 0x6e, 0x65,
      0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x64, 0x76, 0x76, 0x74, 0x70,
      0x35, 0x65, 0x63, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x72, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
      0x05, 0x07, 0x01, 0x01, 0x04, 0x66, 0x30, 0x64, 0x30, 0x32, 0x06, 0x08, 0x2b, 0x06, 0x01,
      0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x26, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70,
      0x72, 0x6f, 0x78, 0x79, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f,
      0x63, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0x00},
     {0x61, 0x2f, 0x64, 0x76, 0x76, 0x74, 0x70, 0x35, 0x65, 0x63, 0x2e, 0x63, 0x72, 0x74, 0x30,
      0x2e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x22, 0x68, 0x74,
      0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x66,
      0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x64, 0x76, 0x76, 0x74, 0x70, 0x35,
      0x65, 0x63, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x05,
      0x00, 0x03, 0x68, 0x00, 0x30, 0x65, 0x02, 0x30, 0x5b, 0x0c, 0x3a, 0x83, 0x70, 0xbb, 0x24,
      0xba, 0x0c, 0x1a, 0x32, 0xf4, 0x9e, 0x42, 0xf4, 0x23, 0x73, 0x98, 0xbc, 0xb4, 0xb2, 0x58,
      0x9c, 0x32, 0xe2, 0xd6, 0xc0, 0x52, 0x80, 0xa7, 0x73, 0x8f, 0x87, 0xa5, 0x52, 0x5e, 0x5b,
      0x82, 0x8d, 0x31, 0x4b, 0x05, 0x4c, 0x4a, 0xe7, 0xde, 0x22, 0x1a, 0x02, 0x31, 0x00, 0xf3,
      0xc3, 0x23, 0x03, 0x27, 0x7e, 0xd8, 0x6b, 0xf0, 0xbc, 0x12, 0xcf, 0x7a, 0xb0, 0x5c, 0x3c,
      0x07, 0xe7, 0x4c, 0x49, 0xcd, 0xb3, 0x12, 0x23, 0xef, 0x78, 0x9f, 0xb8, 0x52, 0xf7, 0x77,
      0xfa, 0xd9, 0xdf, 0xfa, 0x9f, 0x9a, 0x0e, 0xa0, 0x7b, 0xe6, 0xe2, 0xe4, 0x5f, 0x95, 0x0d,
      0xff, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x04, 0x3e, 0x00}, {0x7d, 0x90, 0x00}},

    // 2. PIN Retry count
    // Get retry count
    {{0x00, 0xcb, 0x00, 0xff, 0x05, 0xa0, 0x03, 0x83, 0x01, 0x11, 0x00},
     {0xa0, 0x23, 0x83, 0x01, 0x11, 0x8c, 0x04, 0xf0, 0x00, 0x00, 0x00, 0x9c, 0x04,
      0xf0, 0x00, 0x00, 0x00, 0xdf, 0x21, 0x04, 0x05, 0xff, 0xa5, 0x03, 0xdf, 0x27,
      0x02, 0xff, 0xff, 0xdf, 0x28, 0x01, 0x0c, 0xdf, 0x2f, 0x01, 0x01, 0x90, 0x00}},

    // 3. Authenticate.
    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x11, 0x0c, 0x31, 0x32, 0x33, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00},
     {0x90, 0x00}},

    // Set ENV
    {{0x00, 0x22, 0x41, 0xb6, 0x06, 0x80, 0x01, 0x54, 0x84, 0x01, 0x01}, {0x90, 0x00}},

    // Set Hash
    {{0x00, 0x2a, 0x90, 0xa0, 0x32, 0x90, 0x30, 0x86, 0x25, 0x5f, 0xa2, 0xc3, 0x6e, 0x4b,
      0x30, 0x96, 0x9e, 0xae, 0x17, 0xdc, 0x34, 0xc7, 0x72, 0xcb, 0xeb, 0xdf, 0xc5, 0x8b,
      0x58, 0x40, 0x39, 0x00, 0xbe, 0x87, 0x61, 0x4e, 0xb1, 0xa3, 0x4b, 0x87, 0x80, 0x26,
      0x3f, 0x25, 0x5e, 0xb5, 0xe6, 0x5c, 0xa9, 0xbb, 0xb8, 0x64, 0x1c, 0xcc, 0xfe},
     {0x90, 0x00}},

    // Compute signature
    {{0x00, 0x2a, 0x9e, 0x9a, 0x60},
     {0xd4, 0x27, 0xbb, 0xd4, 0x56, 0x7f, 0x89, 0x99, 0x95, 0xb0, 0x74, 0x84, 0x82, 0xba,
      0xc9, 0x11, 0xa1, 0x3e, 0x7f, 0xb0, 0x97, 0x21, 0x5f, 0x41, 0x46, 0x06, 0x28, 0x8a,
      0x37, 0x5a, 0xed, 0x58, 0xc4, 0x06, 0xf5, 0x0b, 0x30, 0xa2, 0x82, 0x3c, 0xb2, 0x38,
      0xe2, 0x3b, 0x0c, 0xea, 0x40, 0xb6, 0xc3, 0x40, 0x19, 0xef, 0x81, 0x87, 0xa0, 0xe2,
      0xfe, 0x78, 0x4e, 0x90, 0x3a, 0x15, 0x27, 0x6f, 0x4b, 0x87, 0x16, 0x60, 0x6e, 0xcc,
      0x2c, 0xdb, 0xf1, 0x8f, 0x34, 0x2f, 0xb6, 0x75, 0xc1, 0x2f, 0x01, 0xa4, 0x65, 0x9b,
      0xf6, 0x60, 0x77, 0xf9, 0x80, 0x8c, 0x12, 0xc7, 0x35, 0xa7, 0x65, 0xbf, 0x90, 0x00}}};

const PcscMock::ApduScript FINEID_V4_SELECT_SIGN_CERTIFICATE_AND_SIGNING {
    // Select main AID.
    {{0x00, 0xA4, 0x04, 0x0C, 0x0C, 0xa0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4b, 0x43, 0x53, 0x2d,
      0x31, 0x35},
     {0x90, 0x00}},
    // Select signing certificate file.
    {{0x00, 0xA4, 0x08, 0x04, 0x04, 0x50, 0x16, 0x43, 0x32, 0x00},
     {0x62, 0x04, 0x81, 0x02, 0x04, 0x78, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0x00},
     {0x30, 0x82, 0x04, 0x74, 0x30, 0x82, 0x03, 0xf8, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x04,
      0x06, 0x1c, 0x09, 0x66, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
      0x03, 0x05, 0x00, 0x30, 0x78, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
      0x02, 0x46, 0x49, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x20, 0x44,
      0x69, 0x67, 0x69, 0x2d, 0x20, 0x6a, 0x61, 0x20, 0x76, 0x61, 0x65, 0x73, 0x74, 0x6f, 0x74,
      0x69, 0x65, 0x74, 0x6f, 0x76, 0x69, 0x72, 0x61, 0x73, 0x74, 0x6f, 0x20, 0x54, 0x45, 0x53,
      0x54, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0f, 0x54, 0x65, 0x73,
      0x74, 0x69, 0x76, 0x61, 0x72, 0x6d, 0x65, 0x6e, 0x74, 0x65, 0x65, 0x74, 0x31, 0x24, 0x30,
      0x22, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1b, 0x44, 0x56, 0x56, 0x20, 0x54, 0x45, 0x53,
      0x54, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x20,
      0x2d, 0x20, 0x47, 0x35, 0x45, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x33, 0x30, 0x31, 0x32, 0x35,
      0x32, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x32, 0x38, 0x30, 0x31, 0x32, 0x33,
      0x32, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0x00},
     {0x31, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x79, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
      0x04, 0x06, 0x13, 0x02, 0x46, 0x49, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x05,
      0x13, 0x09, 0x39, 0x39, 0x39, 0x30, 0x32, 0x30, 0x33, 0x38, 0x43, 0x31, 0x0f, 0x30, 0x0d,
      0x06, 0x03, 0x55, 0x04, 0x2a, 0x0c, 0x06, 0x50, 0x48, 0x49, 0x4c, 0x49, 0x50, 0x31, 0x19,
      0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x04, 0x0c, 0x10, 0x53, 0x50, 0x45, 0x43, 0x49, 0x4d,
      0x45, 0x4e, 0x2d, 0x41, 0x55, 0x56, 0x49, 0x4e, 0x45, 0x4e, 0x31, 0x2a, 0x30, 0x28, 0x06,
      0x03, 0x55, 0x04, 0x03, 0x0c, 0x21, 0x53, 0x50, 0x45, 0x43, 0x49, 0x4d, 0x45, 0x4e, 0x2d,
      0x41, 0x55, 0x56, 0x49, 0x4e, 0x45, 0x4e, 0x20, 0x50, 0x48, 0x49, 0x4c, 0x49, 0x50, 0x20,
      0x39, 0x39, 0x39, 0x30, 0x32, 0x30, 0x33, 0x38, 0x43, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07,
      0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03,
      0x62, 0x00, 0x04, 0x69, 0x8c, 0xd4, 0x10, 0xc1, 0x9f, 0xc3, 0x5c, 0x66, 0x44, 0xaf, 0xac,
      0xf7, 0x02, 0x39, 0xcc, 0x87, 0xb5, 0x6b, 0x47, 0xb9, 0x34, 0xf3, 0x56, 0xc5, 0x86, 0x45,
      0x2c, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0x00},
     {0x64, 0x94, 0xe1, 0x1f, 0x6c, 0xb0, 0x20, 0xc7, 0x8e, 0x57, 0x33, 0xfc, 0xb0, 0xca, 0xb1,
      0x92, 0xde, 0x77, 0x6c, 0xf5, 0x1e, 0x43, 0xae, 0x74, 0x56, 0xd1, 0x61, 0xc7, 0xb1, 0x50,
      0xa1, 0x91, 0x27, 0x74, 0x2e, 0xb9, 0x78, 0xd8, 0x97, 0x57, 0x9a, 0x45, 0x9b, 0x8c, 0x33,
      0xfa, 0x80, 0x21, 0x2a, 0xb9, 0xd4, 0xeb, 0xf9, 0x9e, 0xf5, 0xe6, 0xf8, 0x71, 0x0b, 0x24,
      0x68, 0x07, 0x1e, 0xe0, 0x87, 0x6f, 0x2c, 0xba, 0xa3, 0x82, 0x02, 0x4e, 0x30, 0x82, 0x02,
      0x4a, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x12,
      0x9e, 0xb7, 0xe2, 0x28, 0xc7, 0xf3, 0x94, 0x6a, 0x8b, 0xbd, 0x4d, 0xc6, 0xf4, 0xc2, 0x36,
      0x97, 0x52, 0x42, 0x08, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14,
      0xe3, 0x66, 0x22, 0xb0, 0x23, 0x72, 0xed, 0x39, 0xb8, 0xf8, 0xfe, 0x2e, 0x7d, 0x85, 0x85,
      0xa9, 0x63, 0x0b, 0x37, 0x07, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
      0x04, 0x04, 0x03, 0x02, 0x06, 0x40, 0x30, 0x81, 0xcd, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
      0x81, 0xc5, 0x30, 0x81, 0xc2, 0x30, 0x81, 0xbf, 0x06, 0x0a, 0x2a, 0x81, 0x76, 0x84, 0x05,
      0x63, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0x00},
     {0x0a, 0x82, 0x60, 0x01, 0x30, 0x81, 0xb0, 0x30, 0x27, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
      0x05, 0x07, 0x02, 0x01, 0x16, 0x1b, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
      0x77, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x70, 0x73,
      0x39, 0x39, 0x2f, 0x30, 0x81, 0x84, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02,
      0x02, 0x30, 0x78, 0x1a, 0x76, 0x56, 0x61, 0x72, 0x6d, 0x65, 0x6e, 0x6e, 0x65, 0x70, 0x6f,
      0x6c, 0x69, 0x74, 0x69, 0x69, 0x6b, 0x6b, 0x61, 0x20, 0x6f, 0x6e, 0x20, 0x73, 0x61, 0x61,
      0x74, 0x61, 0x76, 0x69, 0x6c, 0x6c, 0x61, 0x20, 0x2d, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69,
      0x66, 0x69, 0x6b, 0x61, 0x74, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x20, 0x66, 0x69, 0x6e,
      0x6e, 0x73, 0x20, 0x2d, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
      0x65, 0x20, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x20, 0x69, 0x73, 0x20, 0x61, 0x76, 0x61,
      0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77,
      0x77, 0x77, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x70,
      0x73, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0x00},
     {0x39, 0x39, 0x30, 0x30, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x29, 0x30, 0x27, 0x81, 0x25,
      0x53, 0x31, 0x50, 0x68, 0x69, 0x6c, 0x69, 0x70, 0x30, 0x38, 0x37, 0x2e, 0x53, 0x50, 0x45,
      0x43, 0x49, 0x4d, 0x45, 0x4e, 0x2d, 0x41, 0x75, 0x76, 0x69, 0x6e, 0x65, 0x6e, 0x40, 0x74,
      0x65, 0x73, 0x74, 0x69, 0x2e, 0x66, 0x69, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
      0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0x00, 0x30, 0x38, 0x06, 0x03, 0x55, 0x1d,
      0x1f, 0x04, 0x31, 0x30, 0x2f, 0x30, 0x2d, 0xa0, 0x2b, 0xa0, 0x29, 0x86, 0x27, 0x68, 0x74,
      0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x66, 0x69, 0x6e, 0x65,
      0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x63, 0x72, 0x6c, 0x2f, 0x64, 0x76, 0x76, 0x74, 0x70,
      0x35, 0x65, 0x63, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x72, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
      0x05, 0x07, 0x01, 0x01, 0x04, 0x66, 0x30, 0x64, 0x30, 0x32, 0x06, 0x08, 0x2b, 0x06, 0x01,
      0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x26, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70,
      0x72, 0x6f, 0x78, 0x79, 0x2e, 0x66, 0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f,
      0x63, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0x00},
     {0x61, 0x2f, 0x64, 0x76, 0x76, 0x74, 0x70, 0x35, 0x65, 0x63, 0x2e, 0x63, 0x72, 0x74, 0x30,
      0x2e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x22, 0x68, 0x74,
      0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x6f, 0x63, 0x73, 0x70, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x66,
      0x69, 0x6e, 0x65, 0x69, 0x64, 0x2e, 0x66, 0x69, 0x2f, 0x64, 0x76, 0x76, 0x74, 0x70, 0x35,
      0x65, 0x63, 0x30, 0x37, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x03, 0x04,
      0x2b, 0x30, 0x29, 0x30, 0x08, 0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01, 0x01, 0x30, 0x13,
      0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01, 0x06, 0x30, 0x09, 0x06, 0x07, 0x04, 0x00, 0x8e,
      0x46, 0x01, 0x06, 0x01, 0x30, 0x08, 0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01, 0x04, 0x30,
      0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x05, 0x00, 0x03, 0x68,
      0x00, 0x30, 0x65, 0x02, 0x31, 0x00, 0xcf, 0x0f, 0x09, 0x38, 0x65, 0xc4, 0x6b, 0xf5, 0x32,
      0x24, 0x77, 0xd2, 0xf3, 0x20, 0x20, 0x29, 0xd1, 0xdd, 0x2a, 0x8d, 0x0b, 0xd2, 0xd6, 0x61,
      0x57, 0xa9, 0x9f, 0x85, 0x52, 0xaa, 0x59, 0x51, 0x83, 0x46, 0xca, 0x3c, 0xa6, 0x9f, 0x24,
      0x0f, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x04, 0x3e, 0x00},
     {0xba, 0x9f, 0x4a, 0x7d, 0xb5, 0xf5, 0x40, 0x13, 0x02, 0x30, 0x14, 0x16, 0xe5, 0x2d, 0x53,
      0x54, 0xf5, 0x30, 0x53, 0xdc, 0x55, 0xee, 0xec, 0x2c, 0xa2, 0x42, 0x45, 0xff, 0x71, 0xae,
      0xdb, 0xc8, 0x3a, 0xe1, 0xc1, 0xd6, 0x66, 0x58, 0xf1, 0x67, 0xcb, 0x07, 0x4b, 0x25, 0xbf,
      0xcb, 0x24, 0x20, 0x56, 0x9f, 0x17, 0xc1, 0x68, 0x59, 0x3f, 0x64, 0x0f, 0x50, 0x90, 0x00}},

    // 2. PIN Retry count
    // Get retry count
    {{0x00, 0xcb, 0x00, 0xff, 0x05, 0xa0, 0x03, 0x83, 0x01, 0x82, 0x00},
     {0xa0, 0x23, 0x83, 0x01, 0x82, 0x8c, 0x04, 0xf0, 0x00, 0x00, 0x00, 0x9c, 0x04,
      0xf0, 0x00, 0x00, 0x00, 0xdf, 0x21, 0x04, 0x05, 0xff, 0xa5, 0x03, 0xdf, 0x27,
      0x02, 0xff, 0xff, 0xdf, 0x28, 0x01, 0x0c, 0xdf, 0x2f, 0x01, 0x01, 0x90, 0x00}},

    // 3. Signing.
    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x82, 0x0c, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00},
     {0x90, 0x00}},

    // Set ENV
    {{0x00, 0x22, 0x41, 0xb6, 0x06, 0x80, 0x01, 0x54, 0x84, 0x01, 0x02}, {0x90, 0x00}},

    // Set Hash
    {{0x00, 0x2a, 0x90, 0xa0, 0x32, 0x90, 0x30, 0x86, 0x25, 0x5f, 0xa2, 0xc3, 0x6e, 0x4b,
      0x30, 0x96, 0x9e, 0xae, 0x17, 0xdc, 0x34, 0xc7, 0x72, 0xcb, 0xeb, 0xdf, 0xc5, 0x8b,
      0x58, 0x40, 0x39, 0x00, 0xbe, 0x87, 0x61, 0x4e, 0xb1, 0xa3, 0x4b, 0x87, 0x80, 0x26,
      0x3f, 0x25, 0x5e, 0xb5, 0xe6, 0x5c, 0xa9, 0xbb, 0xb8, 0x64, 0x1c, 0xcc, 0xfe},
     {0x90, 0x00}},

    // Compute signature
    {{0x00, 0x2a, 0x9e, 0x9a, 0x60},
     {0x0a, 0x3e, 0x09, 0x68, 0x5f, 0xe5, 0x2c, 0x43, 0x8a, 0x3a, 0x54, 0x1b, 0x01, 0x39,
      0x3b, 0xb6, 0x10, 0x85, 0x34, 0xed, 0x40, 0x42, 0x53, 0x18, 0x2a, 0x6e, 0xad, 0x2f,
      0x6f, 0x06, 0x34, 0x16, 0x77, 0x6c, 0xc1, 0xaf, 0x3f, 0xe3, 0x4e, 0xd5, 0xbb, 0x82,
      0xf6, 0xc7, 0x72, 0xa0, 0x9b, 0x7d, 0x95, 0x77, 0x62, 0x7f, 0xfd, 0x26, 0x17, 0xe5,
      0x6e, 0x82, 0xcd, 0x6a, 0x21, 0x57, 0x9b, 0xd5, 0x63, 0x93, 0x1b, 0x4c, 0x8a, 0x1a,
      0xb8, 0xe3, 0x3f, 0x1f, 0xed, 0x44, 0xa0, 0x3f, 0x81, 0x6d, 0x22, 0x36, 0xcb, 0xde,
      0x9e, 0x17, 0x97, 0x80, 0x44, 0xce, 0x1e, 0xe5, 0x99, 0xc4, 0x8c, 0x9a, 0x90, 0x00}}};
