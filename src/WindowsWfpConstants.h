// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
// Windows SDK identifier values missing from mingw-w64's public headers.
// Values checked against Microsoft win32metadata RecompiledIdlHeaders/um/fwpmu.h:
// SHA-256 643f2f0c6ebdfa7fe234428b9bfeb2e7c4bbcbe1a5892abddc46bee69a36ea76.
// https://github.com/microsoft/win32metadata/tree/main/generation/WinSDK/RecompiledIdlHeaders
// Project-local constants avoid depending on MinGW's incomplete GUID library.
#ifdef __MINGW32__
namespace OcguiWfp {
inline constexpr GUID FWPM_CONDITION_ALE_APP_ID{ 0xd78e1e87, 0x8644, 0x4ea5, { 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 } };
inline constexpr GUID FWPM_CONDITION_ALE_USER_ID{ 0xaf043a0a, 0xb34d, 0x4f86, { 0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66 } };
inline constexpr GUID FWPM_CONDITION_FLAGS{ 0x632ce23b, 0x5167, 0x435c, { 0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c } };
inline constexpr GUID FWPM_CONDITION_IP_ARRIVAL_INTERFACE{ 0x618a9b6d, 0x386b, 0x4136, { 0xad, 0x6e, 0xb5, 0x15, 0x87, 0xcf, 0xb1, 0xcd } };
inline constexpr GUID FWPM_CONDITION_IP_LOCAL_ADDRESS{ 0xd9ee00de, 0xc1ef, 0x4617, { 0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57 } };
inline constexpr GUID FWPM_CONDITION_IP_LOCAL_PORT{ 0x0c1ba1af, 0x5765, 0x453f, { 0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b } };
inline constexpr GUID FWPM_CONDITION_IP_NEXTHOP_INTERFACE{ 0x93ae8f5b, 0x7f6f, 0x4719, { 0x98, 0xc8, 0x14, 0xe9, 0x74, 0x29, 0xef, 0x04 } };
inline constexpr GUID FWPM_CONDITION_IP_PROTOCOL{ 0x3971ef2b, 0x623e, 0x4f9a, { 0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7 } };
inline constexpr GUID FWPM_CONDITION_IP_REMOTE_ADDRESS{ 0xb235ae9a, 0x1d64, 0x49b8, { 0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45 } };
inline constexpr GUID FWPM_CONDITION_IP_REMOTE_PORT{ 0xc35a604d, 0xd22b, 0x4e1a, { 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b } };
inline constexpr GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4{ 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };
inline constexpr GUID FWPM_LAYER_ALE_AUTH_CONNECT_V6{ 0x4a72393b, 0x319f, 0x44bc, { 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4 } };
inline constexpr GUID FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4{ 0xe1cd9fe7, 0xf4b5, 0x4273, { 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 } };
inline constexpr GUID FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6{ 0xa3b42c97, 0x9f04, 0x4672, { 0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f } };
}
#define FWPM_CONDITION_ALE_APP_ID OcguiWfp::FWPM_CONDITION_ALE_APP_ID
#define FWPM_CONDITION_ALE_USER_ID OcguiWfp::FWPM_CONDITION_ALE_USER_ID
#define FWPM_CONDITION_FLAGS OcguiWfp::FWPM_CONDITION_FLAGS
#define FWPM_CONDITION_IP_ARRIVAL_INTERFACE OcguiWfp::FWPM_CONDITION_IP_ARRIVAL_INTERFACE
#define FWPM_CONDITION_IP_LOCAL_ADDRESS OcguiWfp::FWPM_CONDITION_IP_LOCAL_ADDRESS
#define FWPM_CONDITION_IP_LOCAL_PORT OcguiWfp::FWPM_CONDITION_IP_LOCAL_PORT
#define FWPM_CONDITION_IP_NEXTHOP_INTERFACE OcguiWfp::FWPM_CONDITION_IP_NEXTHOP_INTERFACE
#define FWPM_CONDITION_IP_PROTOCOL OcguiWfp::FWPM_CONDITION_IP_PROTOCOL
#define FWPM_CONDITION_IP_REMOTE_ADDRESS OcguiWfp::FWPM_CONDITION_IP_REMOTE_ADDRESS
#define FWPM_CONDITION_IP_REMOTE_PORT OcguiWfp::FWPM_CONDITION_IP_REMOTE_PORT
#define FWPM_LAYER_ALE_AUTH_CONNECT_V4 OcguiWfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4
#define FWPM_LAYER_ALE_AUTH_CONNECT_V6 OcguiWfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6
#define FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 OcguiWfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
#define FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 OcguiWfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif
#ifndef FWPM_PROVIDER_FLAG_PERSISTENT
#define FWPM_PROVIDER_FLAG_PERSISTENT 0x00000001
#endif
#ifndef FWPM_SUBLAYER_FLAG_PERSISTENT
#define FWPM_SUBLAYER_FLAG_PERSISTENT 0x00000001
#endif
#ifndef FWPM_FILTER_FLAG_PERSISTENT
#define FWPM_FILTER_FLAG_PERSISTENT 0x00000001
#endif
#endif
