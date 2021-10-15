/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

const PcscMock::ApduScript ESTEID_GEMALTO_V3_5_8_GET_AUTH_CERTIFICATE_AND_AUTHENTICATE = {
    // 1. Get certificate.

    // Select master file.
    {{0x00, 0xa4, 0x00, 0x0c}, {0x90, 0x00}},
    // Select EE directory.
    {{0x00, 0xa4, 0x01, 0x0c, 0x02, 0xee, 0xee}, {0x90, 0x00}},
    // Select authentication certificate file.
    {{0x00, 0xa4, 0x02, 0x0c, 0x02, 0xaa, 0xce}, {0x90, 0x00}},

    // Read data length.
    {{0x00, 0xb0, 0x00, 0x00, 0x04}, {0x30, 0x82, 0x06, 0x47, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0xb5},
     {0x30, 0x82, 0x06, 0x47, 0x30, 0x82, 0x04, 0x2f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,
      0x44, 0x0e, 0xd7, 0xd0, 0xfc, 0x91, 0x17, 0x6f, 0x59, 0xd4, 0xcd, 0x76, 0x0e, 0x0b, 0x7e,
      0xc7, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
      0x00, 0x30, 0x6b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x45,
      0x45, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x19, 0x41, 0x53, 0x20,
      0x53, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x74, 0x73, 0x65, 0x65, 0x72, 0x69, 0x6d, 0x69,
      0x73, 0x6b, 0x65, 0x73, 0x6b, 0x75, 0x73, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04,
      0x61, 0x0c, 0x0e, 0x4e, 0x54, 0x52, 0x45, 0x45, 0x2d, 0x31, 0x30, 0x37, 0x34, 0x37, 0x30,
      0x31, 0x33, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x54, 0x45,
      0x53, 0x54, 0x20, 0x6f, 0x66, 0x20, 0x45, 0x53, 0x54, 0x45, 0x49, 0x44, 0x2d, 0x53, 0x4b,
      0x20, 0x32, 0x30, 0x31, 0x35, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x31, 0x30, 0x30, 0x34,
      0x31, 0x32, 0x30, 0x30, 0x35, 0x34, 0x5a, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x39, 0x32, 0x30,
      0x32, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0xb5},
     {0x30, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81, 0x9b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
      0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x45, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
      0x0a, 0x0c, 0x06, 0x45, 0x53, 0x54, 0x45, 0x49, 0x44, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03,
      0x55, 0x04, 0x0b, 0x0c, 0x0e, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61,
      0x74, 0x69, 0x6f, 0x6e, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1d,
      0x4d, 0xc3, 0x84, 0x4e, 0x4e, 0x49, 0x4b, 0x2c, 0x4d, 0x41, 0x52, 0x49, 0x2d, 0x4c, 0x49,
      0x49, 0x53, 0x2c, 0x36, 0x31, 0x37, 0x30, 0x39, 0x32, 0x31, 0x30, 0x31, 0x32, 0x35, 0x31,
      0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x04, 0x0c, 0x07, 0x4d, 0xc3, 0x84, 0x4e, 0x4e,
      0x49, 0x4b, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x2a, 0x0c, 0x09, 0x4d, 0x41,
      0x52, 0x49, 0x2d, 0x4c, 0x49, 0x49, 0x53, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
      0x05, 0x13, 0x0b, 0x36, 0x31, 0x37, 0x30, 0x39, 0x32, 0x31, 0x30, 0x31, 0x32, 0x35, 0x30,
      0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
      0x81, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0xb5},
     {0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xfe, 0xf9, 0x34, 0x75, 0x21, 0xd5, 0xe5, 0x2f,
      0x29, 0xe6, 0xd1, 0x2c, 0x45, 0x54, 0x7c, 0xac, 0xe1, 0x74, 0xdf, 0xc7, 0x54, 0x28, 0x75,
      0x97, 0x8b, 0x0c, 0xd8, 0x30, 0xf8, 0xf6, 0x47, 0x3b, 0xbb, 0x0e, 0xc3, 0xe7, 0xdd, 0xff,
      0xe2, 0x8a, 0xb8, 0x3f, 0xfb, 0x95, 0x54, 0x69, 0x7e, 0x25, 0x3d, 0xc8, 0xc3, 0xde, 0xf2,
      0xa4, 0x78, 0xec, 0x08, 0x78, 0x23, 0xb8, 0xef, 0x9c, 0x9b, 0xce, 0xc9, 0xd7, 0xc0, 0xbc,
      0x8f, 0x33, 0x48, 0xbd, 0x21, 0xf3, 0x4c, 0x49, 0x91, 0x95, 0x91, 0x2d, 0x63, 0x47, 0x69,
      0xe7, 0x34, 0xcd, 0x5f, 0x75, 0xd5, 0x24, 0xad, 0x56, 0xb0, 0xcd, 0xdf, 0xc6, 0xa3, 0x82,
      0x02, 0x62, 0x30, 0x82, 0x02, 0x5e, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02,
      0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
      0x02, 0x03, 0x88, 0x30, 0x81, 0x89, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x81, 0x81, 0x30,
      0x7f, 0x30, 0x73, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xce, 0x1f, 0x03, 0x01, 0x30,
      0x66, 0x30, 0x2f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x23,
      0x68, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0xb5},
     {0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x73, 0x6b, 0x2e, 0x65,
      0x65, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x6f, 0x72, 0x69, 0x75, 0x6d,
      0x2f, 0x43, 0x50, 0x53, 0x30, 0x33, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02,
      0x02, 0x30, 0x27, 0x0c, 0x25, 0x41, 0x69, 0x6e, 0x75, 0x6c, 0x74, 0x20, 0x74, 0x65, 0x73,
      0x74, 0x69, 0x6d, 0x69, 0x73, 0x65, 0x6b, 0x73, 0x2e, 0x20, 0x4f, 0x6e, 0x6c, 0x79, 0x20,
      0x66, 0x6f, 0x72, 0x20, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x30, 0x08, 0x06,
      0x06, 0x04, 0x00, 0x8f, 0x7a, 0x01, 0x02, 0x30, 0x27, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04,
      0x20, 0x30, 0x1e, 0x81, 0x1c, 0x6d, 0x61, 0x72, 0x69, 0x2d, 0x6c, 0x69, 0x69, 0x73, 0x2e,
      0x6d, 0x61, 0x6e, 0x6e, 0x69, 0x6b, 0x2e, 0x38, 0x37, 0x40, 0x65, 0x65, 0x73, 0x74, 0x69,
      0x2e, 0x65, 0x65, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x91,
      0x2b, 0x18, 0xbf, 0xc6, 0x5c, 0x01, 0xe6, 0xa2, 0x2e, 0xdd, 0x7a, 0x59, 0xb3, 0xfd, 0x07,
      0x88, 0xf1, 0x8b, 0x56, 0x30, 0x61, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01,
      0x03, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0xb5},
     {0x04, 0x55, 0x30, 0x53, 0x30, 0x51, 0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01, 0x05, 0x30,
      0x47, 0x30, 0x45, 0x16, 0x3f, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x73, 0x6b,
      0x2e, 0x65, 0x65, 0x2f, 0x65, 0x6e, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f,
      0x72, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2d, 0x66,
      0x6f, 0x72, 0x2d, 0x75, 0x73, 0x65, 0x2d, 0x6f, 0x66, 0x2d, 0x63, 0x65, 0x72, 0x74, 0x69,
      0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x2f, 0x13, 0x02, 0x45, 0x4e, 0x30, 0x20, 0x06,
      0x03, 0x55, 0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2b, 0x06,
      0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03,
      0x04, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x49,
      0xc0, 0xf2, 0x44, 0x39, 0x65, 0xd5, 0x9b, 0x46, 0x3b, 0x0d, 0x38, 0x60, 0x83, 0xb1, 0xd6,
      0x2d, 0x28, 0x86, 0xa6, 0x30, 0x81, 0x83, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
      0x01, 0x01, 0x04, 0x77, 0x30, 0x75, 0x30, 0x2c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
      0x07, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0xb5},
     {0x30, 0x01, 0x86, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61, 0x69, 0x61, 0x2e,
      0x64, 0x65, 0x6d, 0x6f, 0x2e, 0x73, 0x6b, 0x2e, 0x65, 0x65, 0x2f, 0x65, 0x73, 0x74, 0x65,
      0x69, 0x64, 0x32, 0x30, 0x31, 0x35, 0x30, 0x45, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
      0x07, 0x30, 0x02, 0x86, 0x39, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x73, 0x6b,
      0x2e, 0x65, 0x65, 0x2f, 0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x2f, 0x66, 0x69, 0x6c, 0x65,
      0x73, 0x2f, 0x54, 0x45, 0x53, 0x54, 0x5f, 0x6f, 0x66, 0x5f, 0x45, 0x53, 0x54, 0x45, 0x49,
      0x44, 0x2d, 0x53, 0x4b, 0x5f, 0x32, 0x30, 0x31, 0x35, 0x2e, 0x64, 0x65, 0x72, 0x2e, 0x63,
      0x72, 0x74, 0x30, 0x41, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x3a, 0x30, 0x38, 0x30, 0x36,
      0xa0, 0x34, 0xa0, 0x32, 0x86, 0x30, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x77, 0x77,
      0x77, 0x2e, 0x73, 0x6b, 0x2e, 0x65, 0x65, 0x2f, 0x63, 0x72, 0x6c, 0x73, 0x2f, 0x65, 0x73,
      0x74, 0x65, 0x69, 0x64, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x65, 0x73, 0x74, 0x65, 0x69,
      0x64, 0x32, 0x30, 0x31, 0x35, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
      0x48, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0x3e, 0xb5},
     {0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x20, 0x7c,
      0xcd, 0x30, 0xae, 0x69, 0xa1, 0x6a, 0xcf, 0x87, 0x9e, 0xff, 0x5f, 0x05, 0xe1, 0x31, 0x10,
      0x9d, 0xfb, 0x37, 0x9a, 0x7f, 0x2b, 0x26, 0xd0, 0x63, 0x4f, 0x37, 0x71, 0x33, 0xb7, 0x8e,
      0xe4, 0xb7, 0x54, 0x6a, 0xbd, 0x1c, 0x6d, 0x58, 0x93, 0x35, 0x38, 0xe8, 0x3b, 0x68, 0x63,
      0xe6, 0xae, 0x83, 0xe9, 0x91, 0x07, 0x29, 0x6b, 0xac, 0x2f, 0xff, 0x8a, 0x62, 0xbc, 0xe0,
      0x83, 0x60, 0x33, 0x80, 0x77, 0x4a, 0x51, 0xb7, 0xf7, 0xef, 0x0e, 0x64, 0xce, 0x78, 0x49,
      0xf8, 0x76, 0x04, 0xbd, 0x7a, 0xcd, 0x42, 0x70, 0x6e, 0x33, 0x4b, 0x64, 0x0b, 0xe7, 0x5f,
      0x2e, 0x35, 0x84, 0x59, 0x55, 0xa1, 0xc4, 0xa8, 0x5e, 0x32, 0x95, 0xf1, 0x6b, 0xc6, 0x67,
      0x7f, 0x68, 0xd9, 0x69, 0x7a, 0xa7, 0x2b, 0x61, 0x5f, 0x6d, 0xb4, 0xcf, 0x98, 0x46, 0xe2,
      0xe7, 0xbe, 0xb0, 0x3e, 0xe1, 0x99, 0x4a, 0x97, 0xd6, 0x37, 0x26, 0x45, 0x61, 0xfa, 0xab,
      0xe9, 0xf7, 0xe5, 0x7b, 0x43, 0x0f, 0x89, 0x0b, 0x77, 0x83, 0xf7, 0xbb, 0xb9, 0xcb, 0x50,
      0x43, 0xf2, 0xe4, 0xd9, 0xb1, 0x04, 0x0b, 0x60, 0x75, 0x56, 0x6d, 0x55, 0x96, 0x49, 0x5f,
      0x02, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0xf3, 0xb5},
     {0x68, 0xec, 0xd1, 0xc0, 0x57, 0xd9, 0x6f, 0x6b, 0x53, 0xe1, 0x62, 0x58, 0xe8, 0x22, 0x46,
      0x06, 0xba, 0xef, 0x69, 0x9d, 0x75, 0xf6, 0xb9, 0xf8, 0x28, 0xf4, 0x01, 0xc9, 0xa0, 0x88,
      0x6d, 0x52, 0xb5, 0xc5, 0x6e, 0xee, 0x1a, 0xc7, 0x86, 0xbe, 0x5e, 0x11, 0xcc, 0xde, 0x6e,
      0xfe, 0x34, 0x4b, 0xd3, 0xc9, 0x40, 0x57, 0x89, 0xeb, 0x0f, 0x7a, 0xf2, 0xf2, 0xd3, 0xb3,
      0xdc, 0x97, 0x51, 0x24, 0x4f, 0xf8, 0x82, 0x5e, 0x0a, 0x4f, 0x77, 0x95, 0xda, 0x1c, 0xca,
      0xa4, 0x51, 0xcf, 0xad, 0xd9, 0x5a, 0x8c, 0x24, 0xa7, 0x90, 0x05, 0xe6, 0x92, 0xd1, 0x18,
      0x82, 0x7d, 0x63, 0xf4, 0xb8, 0xe7, 0x83, 0xba, 0xcf, 0x48, 0xc0, 0x68, 0x5f, 0x7e, 0xa6,
      0x43, 0xba, 0x10, 0x24, 0x64, 0x72, 0x92, 0xb7, 0x0b, 0x59, 0xd3, 0x66, 0x86, 0x81, 0x54,
      0x19, 0xd7, 0x2b, 0x05, 0xe0, 0x15, 0xf2, 0x2f, 0x2b, 0x32, 0xbc, 0x03, 0x35, 0xd6, 0x1d,
      0xac, 0x83, 0x92, 0x00, 0x8b, 0xd7, 0xa3, 0x20, 0xb3, 0xd4, 0x81, 0x6c, 0xf7, 0xbe, 0xeb,
      0x21, 0xa9, 0xbf, 0xbb, 0x05, 0xc4, 0x09, 0xd6, 0xef, 0xdf, 0xf6, 0x8b, 0x4b, 0x0c, 0xb6,
      0xea, 0x48, 0x03, 0x66, 0x23, 0xab, 0xdf, 0x6d, 0x5c, 0x15, 0x2d, 0x6f, 0x15, 0x1f, 0x64,
      0x74, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x05, 0xa8, 0xa3},
     {0x20, 0x74, 0xf5, 0x48, 0x30, 0x51, 0xde, 0x86, 0x05, 0x0a, 0xd6, 0x04, 0xdb, 0x28, 0x21,
      0xb0, 0xf1, 0x1a, 0x6f, 0x03, 0xc7, 0xbc, 0xb5, 0xba, 0xa4, 0xa8, 0xfb, 0x81, 0xfc, 0xde,
      0x92, 0xf4, 0x0a, 0x43, 0xd0, 0xbd, 0x86, 0xf3, 0x8a, 0xec, 0xc9, 0x3a, 0xd4, 0x4f, 0xcd,
      0xe1, 0xfd, 0xf4, 0xfe, 0x26, 0xb0, 0xef, 0x8b, 0x53, 0xf0, 0xb9, 0xc6, 0x5c, 0xc9, 0xb5,
      0x7c, 0x86, 0xcc, 0xa0, 0x03, 0x0e, 0x26, 0x5e, 0x3e, 0x5f, 0x29, 0x8b, 0x47, 0xc1, 0x0c,
      0xdb, 0x2f, 0xac, 0x99, 0x44, 0xec, 0x43, 0xdb, 0x2f, 0xdc, 0x86, 0xa1, 0xfe, 0xc7, 0x73,
      0x52, 0xb6, 0xb4, 0x3a, 0xd0, 0x4d, 0xfb, 0x5a, 0x00, 0xc4, 0x17, 0xa5, 0x79, 0x85, 0x92,
      0xcb, 0x7e, 0xf8, 0x4d, 0xa9, 0x5f, 0xa9, 0x6e, 0x11, 0x8f, 0x30, 0x8a, 0xd7, 0x8e, 0x3b,
      0x86, 0xfe, 0xcb, 0xca, 0x15, 0xfe, 0x00, 0xeb, 0x50, 0x33, 0x1b, 0xe2, 0x8e, 0x3d, 0x31,
      0x0f, 0xae, 0x16, 0x35, 0x5f, 0x8e, 0xc2, 0x1a, 0x65, 0x66, 0x89, 0xdd, 0x80, 0x94, 0x62,
      0x8a, 0xff, 0xb9, 0x41, 0xed, 0x9e, 0xd0, 0x3c, 0x8b, 0x72, 0x48, 0x03, 0x99, 0x90, 0x00}},

    // 2. PIN Retry count
    // Select master file.
    {{0x00, 0xa4, 0x00, 0x0c}, {0x90, 0x00}},

    // Select EE directory.
    {{0x00, 0xa4, 0x02, 0x0c, 0x02, 0x00, 0x16}, {0x90, 0x00}},

    // Get retry count
    {{0x00, 0xb2, 0x01, 0x04},
     {0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x90, 0x00}}, // TODO: get correct result

    // 3. Authenticate.
    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x01, 0x04, 0x30, 0x30, 0x39, 0x30}, {0x90, 0x00}},

    // Internal authenticate.
    {{}, {0x90, 0x00}} // Empty command as hash is changing, bogus response.
};

const PcscMock::ApduScript ESTEID_GEMALTO_V3_5_8_GET_SIGN_CERTIFICATE_AND_SIGNING = {
    // 1. Get certificate.

    // Select master file.
    {{0x00, 0xa4, 0x00, 0x0c}, {0x90, 0x00}},
    // Select EE directory.
    {{0x00, 0xa4, 0x01, 0x0c, 0x02, 0xee, 0xee}, {0x90, 0x00}},
    // Select signing certificate file.
    {{0x00, 0xa4, 0x02, 0x0c, 0x02, 0xdd, 0xce}, {0x90, 0x00}},

    // Read data length.
    {{0x00, 0xb0, 0x00, 0x00, 0x04}, {0x30, 0x82, 0x05, 0xc2, 0x90, 0x00}},

    // Read first block.
    {{0x00, 0xb0, 0x00, 0x00, 0xb5},
     {0x30, 0x82, 0x05, 0xc2, 0x30, 0x82, 0x03, 0xaa, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,
      0x52, 0x74, 0x82, 0x52, 0xdd, 0x72, 0x2f, 0x32, 0x59, 0xd4, 0xcd, 0x78, 0x0c, 0xbb, 0xc7,
      0x7f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05,
      0x00, 0x30, 0x6b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x45,
      0x45, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x19, 0x41, 0x53, 0x20,
      0x53, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x74, 0x73, 0x65, 0x65, 0x72, 0x69, 0x6d, 0x69,
      0x73, 0x6b, 0x65, 0x73, 0x6b, 0x75, 0x73, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04,
      0x61, 0x0c, 0x0e, 0x4e, 0x54, 0x52, 0x45, 0x45, 0x2d, 0x31, 0x30, 0x37, 0x34, 0x37, 0x30,
      0x31, 0x33, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x54, 0x45,
      0x53, 0x54, 0x20, 0x6f, 0x66, 0x20, 0x45, 0x53, 0x54, 0x45, 0x49, 0x44, 0x2d, 0x53, 0x4b,
      0x20, 0x32, 0x30, 0x31, 0x35, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x37, 0x31, 0x30, 0x30, 0x34,
      0x31, 0x32, 0x30, 0x30, 0x35, 0x36, 0x5a, 0x17, 0x0d, 0x32, 0x32, 0x30, 0x39, 0x32, 0x30,
      0x32, 0x90, 0x00}},

    // Keep reading blocks until done.
    {{0x00, 0xb0, 0x00, 0xb5, 0xb5},
     {0x30, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x81, 0x9e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
      0x55, 0x04, 0x06, 0x13, 0x02, 0x45, 0x45, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
      0x0a, 0x0c, 0x06, 0x45, 0x53, 0x54, 0x45, 0x49, 0x44, 0x31, 0x1a, 0x30, 0x18, 0x06, 0x03,
      0x55, 0x04, 0x0b, 0x0c, 0x11, 0x64, 0x69, 0x67, 0x69, 0x74, 0x61, 0x6c, 0x20, 0x73, 0x69,
      0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03, 0x55, 0x04,
      0x03, 0x0c, 0x1d, 0x4d, 0xc3, 0x84, 0x4e, 0x4e, 0x49, 0x4b, 0x2c, 0x4d, 0x41, 0x52, 0x49,
      0x2d, 0x4c, 0x49, 0x49, 0x53, 0x2c, 0x36, 0x31, 0x37, 0x30, 0x39, 0x32, 0x31, 0x30, 0x31,
      0x32, 0x35, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x04, 0x0c, 0x07, 0x4d, 0xc3,
      0x84, 0x4e, 0x4e, 0x49, 0x4b, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x2a, 0x0c,
      0x09, 0x4d, 0x41, 0x52, 0x49, 0x2d, 0x4c, 0x49, 0x49, 0x53, 0x31, 0x14, 0x30, 0x12, 0x06,
      0x03, 0x55, 0x04, 0x05, 0x13, 0x0b, 0x36, 0x31, 0x37, 0x30, 0x39, 0x32, 0x31, 0x30, 0x31,
      0x32, 0x35, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
      0x06, 0x90, 0x00}},

    {{0x00, 0xb0, 0x01, 0x6a, 0xb5},
     {0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xba, 0x7c, 0xed, 0x76, 0xaf,
      0x1c, 0x7f, 0xa7, 0xa6, 0x76, 0x67, 0x8e, 0x4f, 0x4c, 0xec, 0x52, 0xe1, 0x81, 0x68, 0x57,
      0x67, 0x23, 0x5b, 0xca, 0x85, 0xaf, 0xbc, 0xdd, 0x9a, 0xa8, 0x64, 0xc7, 0x0e, 0x21, 0x79,
      0x0a, 0x3b, 0x27, 0x6b, 0xf3, 0x20, 0x70, 0x8c, 0x47, 0xe5, 0x41, 0xfd, 0xe4, 0x99, 0x6f,
      0xdd, 0xb2, 0xcc, 0x6e, 0x35, 0x94, 0x29, 0xfc, 0xbc, 0xc2, 0xb9, 0x63, 0x33, 0xb4, 0x81,
      0x2e, 0x1b, 0xe0, 0x1b, 0xfb, 0xc3, 0x05, 0x05, 0x06, 0xb2, 0x6b, 0x18, 0x2b, 0xeb, 0x30,
      0xd8, 0x30, 0xf3, 0xa5, 0x16, 0x5f, 0x1a, 0x43, 0x71, 0x1c, 0xfe, 0xa4, 0x8c, 0x96, 0x00,
      0x5b, 0xa3, 0x82, 0x01, 0xda, 0x30, 0x82, 0x01, 0xd6, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d,
      0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
      0x04, 0x04, 0x03, 0x02, 0x06, 0x40, 0x30, 0x81, 0x8b, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04,
      0x81, 0x83, 0x30, 0x81, 0x80, 0x30, 0x73, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xce,
      0x1f, 0x03, 0x01, 0x30, 0x66, 0x30, 0x2f, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
      0x02, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0x1f, 0xb5},
     {0x01, 0x16, 0x23, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e,
      0x73, 0x6b, 0x2e, 0x65, 0x65, 0x2f, 0x72, 0x65, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x6f, 0x6f,
      0x72, 0x69, 0x75, 0x6d, 0x2f, 0x43, 0x50, 0x53, 0x30, 0x33, 0x06, 0x08, 0x2b, 0x06, 0x01,
      0x05, 0x05, 0x07, 0x02, 0x02, 0x30, 0x27, 0x0c, 0x25, 0x41, 0x69, 0x6e, 0x75, 0x6c, 0x74,
      0x20, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6d, 0x69, 0x73, 0x65, 0x6b, 0x73, 0x2e, 0x20, 0x4f,
      0x6e, 0x6c, 0x79, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67,
      0x2e, 0x30, 0x09, 0x06, 0x07, 0x04, 0x00, 0x8b, 0xec, 0x40, 0x01, 0x02, 0x30, 0x1d, 0x06,
      0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x3e, 0xaa, 0x8f, 0x88, 0x6f, 0x72, 0x05,
      0xb8, 0x14, 0xe0, 0xac, 0x5e, 0xe9, 0x40, 0x33, 0x5a, 0xeb, 0x77, 0xa5, 0x38, 0x30, 0x22,
      0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x03, 0x04, 0x16, 0x30, 0x14, 0x30,
      0x08, 0x06, 0x06, 0x04, 0x00, 0x8e, 0x46, 0x01, 0x01, 0x30, 0x08, 0x06, 0x06, 0x04, 0x00,
      0x8e, 0x46, 0x01, 0x04, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
      0x80, 0x90, 0x00}},

    {{0x00, 0xb0, 0x02, 0xd4, 0xb5},
     {0x14, 0x49, 0xc0, 0xf2, 0x44, 0x39, 0x65, 0xd5, 0x9b, 0x46, 0x3b, 0x0d, 0x38, 0x60, 0x83,
      0xb1, 0xd6, 0x2d, 0x28, 0x86, 0xa6, 0x30, 0x81, 0x83, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
      0x05, 0x07, 0x01, 0x01, 0x04, 0x77, 0x30, 0x75, 0x30, 0x2c, 0x06, 0x08, 0x2b, 0x06, 0x01,
      0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x61,
      0x69, 0x61, 0x2e, 0x64, 0x65, 0x6d, 0x6f, 0x2e, 0x73, 0x6b, 0x2e, 0x65, 0x65, 0x2f, 0x65,
      0x73, 0x74, 0x65, 0x69, 0x64, 0x32, 0x30, 0x31, 0x35, 0x30, 0x45, 0x06, 0x08, 0x2b, 0x06,
      0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x39, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
      0x2f, 0x73, 0x6b, 0x2e, 0x65, 0x65, 0x2f, 0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x2f, 0x66,
      0x69, 0x6c, 0x65, 0x73, 0x2f, 0x54, 0x45, 0x53, 0x54, 0x5f, 0x6f, 0x66, 0x5f, 0x45, 0x53,
      0x54, 0x45, 0x49, 0x44, 0x2d, 0x53, 0x4b, 0x5f, 0x32, 0x30, 0x31, 0x35, 0x2e, 0x64, 0x65,
      0x72, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x41, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x3a, 0x30,
      0x38, 0x30, 0x36, 0xa0, 0x34, 0xa0, 0x32, 0x86, 0x30, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f,
      0x2f, 0x90, 0x00}},

    {{0x00, 0xb0, 0x03, 0x89, 0xb5},
     {0x77, 0x77, 0x77, 0x2e, 0x73, 0x6b, 0x2e, 0x65, 0x65, 0x2f, 0x63, 0x72, 0x6c, 0x73, 0x2f,
      0x65, 0x73, 0x74, 0x65, 0x69, 0x64, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x65, 0x73, 0x74,
      0x65, 0x69, 0x64, 0x32, 0x30, 0x31, 0x35, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x0d, 0x06, 0x09,
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01,
      0x00, 0xc1, 0xee, 0x39, 0x55, 0xf1, 0xf1, 0xca, 0x7b, 0x8e, 0x2d, 0x94, 0x40, 0xe5, 0x4f,
      0xac, 0x4e, 0x9a, 0x53, 0xcd, 0x72, 0x80, 0x44, 0xd4, 0x96, 0xfc, 0xbb, 0x70, 0x04, 0x80,
      0x07, 0x5c, 0xb3, 0x0e, 0xb7, 0x70, 0x9e, 0xa7, 0x23, 0x40, 0x1a, 0x56, 0xe7, 0xad, 0x85,
      0x57, 0x50, 0x5b, 0x21, 0x1b, 0x4a, 0x68, 0xcd, 0xec, 0xbe, 0x12, 0xa3, 0x5d, 0x44, 0xad,
      0xb1, 0x30, 0xf2, 0x1c, 0xc5, 0x36, 0xde, 0x10, 0x37, 0xcf, 0xad, 0xd7, 0x16, 0x1f, 0x50,
      0x47, 0xa6, 0xf6, 0x7e, 0xef, 0x67, 0xad, 0xfe, 0xdd, 0xbb, 0x48, 0x89, 0x2d, 0x63, 0xa8,
      0x44, 0xe8, 0x56, 0x20, 0xeb, 0x67, 0xb4, 0x7d, 0x4f, 0x70, 0xc6, 0xc3, 0xcb, 0xf1, 0xa3,
      0x69, 0x73, 0xac, 0x0e, 0xeb, 0x6a, 0xd4, 0x49, 0xfd, 0x64, 0x9b, 0xd5, 0x8a, 0xd2, 0x1d,
      0xb3, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0x3e, 0xb5},
     {0x9d, 0x7a, 0x76, 0x59, 0x7a, 0x5d, 0x46, 0xb3, 0x12, 0xd5, 0xee, 0x2f, 0xce, 0xe6, 0x83,
      0xe8, 0xda, 0x04, 0x8a, 0x09, 0x90, 0xe0, 0x9f, 0x8f, 0xd9, 0x52, 0xe1, 0xda, 0xcf, 0x65,
      0xfa, 0xa8, 0xf2, 0xea, 0x1b, 0x8b, 0x98, 0x97, 0x9e, 0xb0, 0x42, 0x52, 0x54, 0x11, 0xac,
      0x1b, 0x83, 0x1d, 0xcb, 0xbf, 0x4e, 0x26, 0x67, 0x79, 0xe3, 0xd8, 0xea, 0x87, 0x59, 0x4a,
      0x0f, 0xc0, 0x07, 0xcc, 0x61, 0xbf, 0x7c, 0x09, 0xfd, 0x3e, 0x21, 0x92, 0x1c, 0xe5, 0xc7,
      0xd2, 0xd7, 0x91, 0xca, 0xfd, 0x36, 0x36, 0x42, 0x00, 0x58, 0x42, 0x42, 0x83, 0x97, 0x62,
      0x3f, 0x5e, 0xb9, 0x93, 0xa3, 0x97, 0xde, 0x32, 0x36, 0xf7, 0xc8, 0x2b, 0x4f, 0x28, 0x54,
      0x23, 0xc3, 0x37, 0x8f, 0x0b, 0x50, 0xd6, 0x93, 0x47, 0x30, 0x56, 0x0d, 0x31, 0xf5, 0xeb,
      0xe1, 0xc4, 0xe3, 0x26, 0xfb, 0xb0, 0x10, 0x4f, 0x46, 0xd6, 0x21, 0x33, 0x9a, 0xf2, 0xbb,
      0xf0, 0xac, 0x4c, 0xa3, 0x7a, 0x3b, 0xe2, 0x42, 0x68, 0x44, 0xc3, 0x46, 0x5d, 0xf3, 0x70,
      0x5d, 0x8a, 0x73, 0xab, 0x4a, 0x59, 0x63, 0xac, 0x45, 0x20, 0xda, 0xfe, 0xe5, 0x60, 0xdd,
      0xc7, 0xa6, 0x80, 0x94, 0xe6, 0xf5, 0x77, 0x73, 0x0b, 0x30, 0x7b, 0x7e, 0x95, 0xff, 0xf5,
      0x37, 0x90, 0x00}},

    {{0x00, 0xb0, 0x04, 0xf3, 0xb5},
     {0x31, 0xb8, 0xf2, 0xec, 0xbc, 0xea, 0xe0, 0x73, 0x3a, 0x59, 0xdf, 0x15, 0xbe, 0xd1, 0xf1,
      0xb6, 0xe9, 0x3e, 0xc0, 0x4b, 0x6d, 0x76, 0x16, 0x63, 0x50, 0xf4, 0x1e, 0xf6, 0x29, 0xa8,
      0x71, 0x47, 0x24, 0x6b, 0xa5, 0x42, 0xa0, 0xd5, 0x72, 0xf2, 0xbe, 0x30, 0x78, 0x2b, 0x27,
      0x1c, 0xf4, 0x04, 0x63, 0x72, 0x9d, 0x2b, 0x90, 0x89, 0xd4, 0x2c, 0x4e, 0xe1, 0xff, 0xc1,
      0x3b, 0x57, 0xdb, 0xf3, 0xcd, 0x96, 0x35, 0xc0, 0xcf, 0xc5, 0x8b, 0xc0, 0xf7, 0xda, 0xe2,
      0x34, 0x3e, 0x80, 0x25, 0x0f, 0xc7, 0xf7, 0x9f, 0x96, 0x58, 0x0c, 0xee, 0xe3, 0x34, 0xf7,
      0x85, 0x3b, 0xc5, 0x7d, 0xf1, 0xfa, 0x8b, 0xb7, 0x32, 0xa4, 0xeb, 0x70, 0xaa, 0x35, 0xdf,
      0x72, 0x57, 0x49, 0xa3, 0x8b, 0xc7, 0x39, 0x2e, 0x8c, 0xaa, 0x26, 0xf6, 0x55, 0xbd, 0x04,
      0x85, 0x0e, 0x4a, 0xd1, 0x44, 0xcb, 0x00, 0x89, 0x69, 0x2f, 0xc2, 0x0c, 0xed, 0xf9, 0xfe,
      0xfd, 0x24, 0x68, 0xbf, 0xe2, 0x8c, 0x12, 0x26, 0x27, 0x5a, 0x3a, 0x95, 0x4d, 0x0d, 0xd9,
      0x97, 0x0f, 0x54, 0x38, 0xad, 0x29, 0x0f, 0x30, 0x2f, 0xec, 0x5b, 0x09, 0xcb, 0x4e, 0x44,
      0xde, 0x3f, 0x04, 0xe9, 0x5a, 0xba, 0x1b, 0x43, 0x70, 0xbf, 0xb1, 0xcb, 0x04, 0xa0, 0xed,
      0x4f, 0x90, 0x00}},

    // Read final block.
    {{0x00, 0xb0, 0x05, 0xa8, 0x1e},
     {0xb8, 0xa6, 0x1f, 0x03, 0xbe, 0xd4, 0xff, 0xbb, 0xa8, 0x38, 0x98,
      0x3e, 0x07, 0xb3, 0x43, 0x2b, 0xe9, 0xf8, 0xbb, 0xee, 0x9b, 0xec,
      0xb5, 0x12, 0xf7, 0x66, 0xd7, 0x5a, 0x8d, 0x04, 0x90, 0x00}},

    // 2. PIN Retry count
    // Select master file.
    {{0x00, 0xa4, 0x00, 0x0c}, {0x90, 0x00}},

    // Select EE directory.
    {{0x00, 0xa4, 0x02, 0x0c, 0x02, 0x00, 0x16}, {0x90, 0x00}},

    // Get retry count
    {{0x00, 0xb2, 0x02, 0x04},
     {0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x90, 0x00}}, // TODO: get correct result

    // 3. Signing.
    // Verify PIN.
    {{0x00, 0x20, 0x00, 0x02}, {0x90, 0x00}}, // TODO: expand response.
    // Internal authenticate.
    {{}, {0x90, 0x00}} // Empty command as hash is changing, bogus response.
};
