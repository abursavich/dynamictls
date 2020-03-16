// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File imported from: https://github.com/golang/net/blob/0ed95abb35c445290478a5348a7b38bb154135fd/http2/ciphers.go
// Underscores replaced with x's to make linters quiet.

package http2

// A list of the possible cipher suite ids. Taken from
// https://www.iana.org/assignments/tls-parameters/tls-parameters.txt

//nolint:unused,varcheck,deadcode
const (
	cipherxTLSxNULLxWITHxNULLxNULL               uint16 = 0x0000
	cipherxTLSxRSAxWITHxNULLxMD5                 uint16 = 0x0001
	cipherxTLSxRSAxWITHxNULLxSHA                 uint16 = 0x0002
	cipherxTLSxRSAxEXPORTxWITHxRC4x40xMD5        uint16 = 0x0003
	cipherxTLSxRSAxWITHxRC4x128xMD5              uint16 = 0x0004
	cipherxTLSxRSAxWITHxRC4x128xSHA              uint16 = 0x0005
	cipherxTLSxRSAxEXPORTxWITHxRC2xCBCx40xMD5    uint16 = 0x0006
	cipherxTLSxRSAxWITHxIDEAxCBCxSHA             uint16 = 0x0007
	cipherxTLSxRSAxEXPORTxWITHxDES40xCBCxSHA     uint16 = 0x0008
	cipherxTLSxRSAxWITHxDESxCBCxSHA              uint16 = 0x0009
	cipherxTLSxRSAxWITHx3DESxEDExCBCxSHA         uint16 = 0x000A
	cipherxTLSxDHxDSSxEXPORTxWITHxDES40xCBCxSHA  uint16 = 0x000B
	cipherxTLSxDHxDSSxWITHxDESxCBCxSHA           uint16 = 0x000C
	cipherxTLSxDHxDSSxWITHx3DESxEDExCBCxSHA      uint16 = 0x000D
	cipherxTLSxDHxRSAxEXPORTxWITHxDES40xCBCxSHA  uint16 = 0x000E
	cipherxTLSxDHxRSAxWITHxDESxCBCxSHA           uint16 = 0x000F
	cipherxTLSxDHxRSAxWITHx3DESxEDExCBCxSHA      uint16 = 0x0010
	cipherxTLSxDHExDSSxEXPORTxWITHxDES40xCBCxSHA uint16 = 0x0011
	cipherxTLSxDHExDSSxWITHxDESxCBCxSHA          uint16 = 0x0012
	cipherxTLSxDHExDSSxWITHx3DESxEDExCBCxSHA     uint16 = 0x0013
	cipherxTLSxDHExRSAxEXPORTxWITHxDES40xCBCxSHA uint16 = 0x0014
	cipherxTLSxDHExRSAxWITHxDESxCBCxSHA          uint16 = 0x0015
	cipherxTLSxDHExRSAxWITHx3DESxEDExCBCxSHA     uint16 = 0x0016
	cipherxTLSxDHxanonxEXPORTxWITHxRC4x40xMD5    uint16 = 0x0017
	cipherxTLSxDHxanonxWITHxRC4x128xMD5          uint16 = 0x0018
	cipherxTLSxDHxanonxEXPORTxWITHxDES40xCBCxSHA uint16 = 0x0019
	cipherxTLSxDHxanonxWITHxDESxCBCxSHA          uint16 = 0x001A
	cipherxTLSxDHxanonxWITHx3DESxEDExCBCxSHA     uint16 = 0x001B
	// Reserved uint16 =  0x001C-1D
	cipherxTLSxKRB5xWITHxDESxCBCxSHA             uint16 = 0x001E
	cipherxTLSxKRB5xWITHx3DESxEDExCBCxSHA        uint16 = 0x001F
	cipherxTLSxKRB5xWITHxRC4x128xSHA             uint16 = 0x0020
	cipherxTLSxKRB5xWITHxIDEAxCBCxSHA            uint16 = 0x0021
	cipherxTLSxKRB5xWITHxDESxCBCxMD5             uint16 = 0x0022
	cipherxTLSxKRB5xWITHx3DESxEDExCBCxMD5        uint16 = 0x0023
	cipherxTLSxKRB5xWITHxRC4x128xMD5             uint16 = 0x0024
	cipherxTLSxKRB5xWITHxIDEAxCBCxMD5            uint16 = 0x0025
	cipherxTLSxKRB5xEXPORTxWITHxDESxCBCx40xSHA   uint16 = 0x0026
	cipherxTLSxKRB5xEXPORTxWITHxRC2xCBCx40xSHA   uint16 = 0x0027
	cipherxTLSxKRB5xEXPORTxWITHxRC4x40xSHA       uint16 = 0x0028
	cipherxTLSxKRB5xEXPORTxWITHxDESxCBCx40xMD5   uint16 = 0x0029
	cipherxTLSxKRB5xEXPORTxWITHxRC2xCBCx40xMD5   uint16 = 0x002A
	cipherxTLSxKRB5xEXPORTxWITHxRC4x40xMD5       uint16 = 0x002B
	cipherxTLSxPSKxWITHxNULLxSHA                 uint16 = 0x002C
	cipherxTLSxDHExPSKxWITHxNULLxSHA             uint16 = 0x002D
	cipherxTLSxRSAxPSKxWITHxNULLxSHA             uint16 = 0x002E
	cipherxTLSxRSAxWITHxAESx128xCBCxSHA          uint16 = 0x002F
	cipherxTLSxDHxDSSxWITHxAESx128xCBCxSHA       uint16 = 0x0030
	cipherxTLSxDHxRSAxWITHxAESx128xCBCxSHA       uint16 = 0x0031
	cipherxTLSxDHExDSSxWITHxAESx128xCBCxSHA      uint16 = 0x0032
	cipherxTLSxDHExRSAxWITHxAESx128xCBCxSHA      uint16 = 0x0033
	cipherxTLSxDHxanonxWITHxAESx128xCBCxSHA      uint16 = 0x0034
	cipherxTLSxRSAxWITHxAESx256xCBCxSHA          uint16 = 0x0035
	cipherxTLSxDHxDSSxWITHxAESx256xCBCxSHA       uint16 = 0x0036
	cipherxTLSxDHxRSAxWITHxAESx256xCBCxSHA       uint16 = 0x0037
	cipherxTLSxDHExDSSxWITHxAESx256xCBCxSHA      uint16 = 0x0038
	cipherxTLSxDHExRSAxWITHxAESx256xCBCxSHA      uint16 = 0x0039
	cipherxTLSxDHxanonxWITHxAESx256xCBCxSHA      uint16 = 0x003A
	cipherxTLSxRSAxWITHxNULLxSHA256              uint16 = 0x003B
	cipherxTLSxRSAxWITHxAESx128xCBCxSHA256       uint16 = 0x003C
	cipherxTLSxRSAxWITHxAESx256xCBCxSHA256       uint16 = 0x003D
	cipherxTLSxDHxDSSxWITHxAESx128xCBCxSHA256    uint16 = 0x003E
	cipherxTLSxDHxRSAxWITHxAESx128xCBCxSHA256    uint16 = 0x003F
	cipherxTLSxDHExDSSxWITHxAESx128xCBCxSHA256   uint16 = 0x0040
	cipherxTLSxRSAxWITHxCAMELLIAx128xCBCxSHA     uint16 = 0x0041
	cipherxTLSxDHxDSSxWITHxCAMELLIAx128xCBCxSHA  uint16 = 0x0042
	cipherxTLSxDHxRSAxWITHxCAMELLIAx128xCBCxSHA  uint16 = 0x0043
	cipherxTLSxDHExDSSxWITHxCAMELLIAx128xCBCxSHA uint16 = 0x0044
	cipherxTLSxDHExRSAxWITHxCAMELLIAx128xCBCxSHA uint16 = 0x0045
	cipherxTLSxDHxanonxWITHxCAMELLIAx128xCBCxSHA uint16 = 0x0046
	// Reserved uint16 =  0x0047-4F
	// Reserved uint16 =  0x0050-58
	// Reserved uint16 =  0x0059-5C
	// Unassigned uint16 =  0x005D-5F
	// Reserved uint16 =  0x0060-66
	cipherxTLSxDHExRSAxWITHxAESx128xCBCxSHA256 uint16 = 0x0067
	cipherxTLSxDHxDSSxWITHxAESx256xCBCxSHA256  uint16 = 0x0068
	cipherxTLSxDHxRSAxWITHxAESx256xCBCxSHA256  uint16 = 0x0069
	cipherxTLSxDHExDSSxWITHxAESx256xCBCxSHA256 uint16 = 0x006A
	cipherxTLSxDHExRSAxWITHxAESx256xCBCxSHA256 uint16 = 0x006B
	cipherxTLSxDHxanonxWITHxAESx128xCBCxSHA256 uint16 = 0x006C
	cipherxTLSxDHxanonxWITHxAESx256xCBCxSHA256 uint16 = 0x006D
	// Unassigned uint16 =  0x006E-83
	cipherxTLSxRSAxWITHxCAMELLIAx256xCBCxSHA        uint16 = 0x0084
	cipherxTLSxDHxDSSxWITHxCAMELLIAx256xCBCxSHA     uint16 = 0x0085
	cipherxTLSxDHxRSAxWITHxCAMELLIAx256xCBCxSHA     uint16 = 0x0086
	cipherxTLSxDHExDSSxWITHxCAMELLIAx256xCBCxSHA    uint16 = 0x0087
	cipherxTLSxDHExRSAxWITHxCAMELLIAx256xCBCxSHA    uint16 = 0x0088
	cipherxTLSxDHxanonxWITHxCAMELLIAx256xCBCxSHA    uint16 = 0x0089
	cipherxTLSxPSKxWITHxRC4x128xSHA                 uint16 = 0x008A
	cipherxTLSxPSKxWITHx3DESxEDExCBCxSHA            uint16 = 0x008B
	cipherxTLSxPSKxWITHxAESx128xCBCxSHA             uint16 = 0x008C
	cipherxTLSxPSKxWITHxAESx256xCBCxSHA             uint16 = 0x008D
	cipherxTLSxDHExPSKxWITHxRC4x128xSHA             uint16 = 0x008E
	cipherxTLSxDHExPSKxWITHx3DESxEDExCBCxSHA        uint16 = 0x008F
	cipherxTLSxDHExPSKxWITHxAESx128xCBCxSHA         uint16 = 0x0090
	cipherxTLSxDHExPSKxWITHxAESx256xCBCxSHA         uint16 = 0x0091
	cipherxTLSxRSAxPSKxWITHxRC4x128xSHA             uint16 = 0x0092
	cipherxTLSxRSAxPSKxWITHx3DESxEDExCBCxSHA        uint16 = 0x0093
	cipherxTLSxRSAxPSKxWITHxAESx128xCBCxSHA         uint16 = 0x0094
	cipherxTLSxRSAxPSKxWITHxAESx256xCBCxSHA         uint16 = 0x0095
	cipherxTLSxRSAxWITHxSEEDxCBCxSHA                uint16 = 0x0096
	cipherxTLSxDHxDSSxWITHxSEEDxCBCxSHA             uint16 = 0x0097
	cipherxTLSxDHxRSAxWITHxSEEDxCBCxSHA             uint16 = 0x0098
	cipherxTLSxDHExDSSxWITHxSEEDxCBCxSHA            uint16 = 0x0099
	cipherxTLSxDHExRSAxWITHxSEEDxCBCxSHA            uint16 = 0x009A
	cipherxTLSxDHxanonxWITHxSEEDxCBCxSHA            uint16 = 0x009B
	cipherxTLSxRSAxWITHxAESx128xGCMxSHA256          uint16 = 0x009C
	cipherxTLSxRSAxWITHxAESx256xGCMxSHA384          uint16 = 0x009D
	cipherxTLSxDHExRSAxWITHxAESx128xGCMxSHA256      uint16 = 0x009E
	cipherxTLSxDHExRSAxWITHxAESx256xGCMxSHA384      uint16 = 0x009F
	cipherxTLSxDHxRSAxWITHxAESx128xGCMxSHA256       uint16 = 0x00A0
	cipherxTLSxDHxRSAxWITHxAESx256xGCMxSHA384       uint16 = 0x00A1
	cipherxTLSxDHExDSSxWITHxAESx128xGCMxSHA256      uint16 = 0x00A2
	cipherxTLSxDHExDSSxWITHxAESx256xGCMxSHA384      uint16 = 0x00A3
	cipherxTLSxDHxDSSxWITHxAESx128xGCMxSHA256       uint16 = 0x00A4
	cipherxTLSxDHxDSSxWITHxAESx256xGCMxSHA384       uint16 = 0x00A5
	cipherxTLSxDHxanonxWITHxAESx128xGCMxSHA256      uint16 = 0x00A6
	cipherxTLSxDHxanonxWITHxAESx256xGCMxSHA384      uint16 = 0x00A7
	cipherxTLSxPSKxWITHxAESx128xGCMxSHA256          uint16 = 0x00A8
	cipherxTLSxPSKxWITHxAESx256xGCMxSHA384          uint16 = 0x00A9
	cipherxTLSxDHExPSKxWITHxAESx128xGCMxSHA256      uint16 = 0x00AA
	cipherxTLSxDHExPSKxWITHxAESx256xGCMxSHA384      uint16 = 0x00AB
	cipherxTLSxRSAxPSKxWITHxAESx128xGCMxSHA256      uint16 = 0x00AC
	cipherxTLSxRSAxPSKxWITHxAESx256xGCMxSHA384      uint16 = 0x00AD
	cipherxTLSxPSKxWITHxAESx128xCBCxSHA256          uint16 = 0x00AE
	cipherxTLSxPSKxWITHxAESx256xCBCxSHA384          uint16 = 0x00AF
	cipherxTLSxPSKxWITHxNULLxSHA256                 uint16 = 0x00B0
	cipherxTLSxPSKxWITHxNULLxSHA384                 uint16 = 0x00B1
	cipherxTLSxDHExPSKxWITHxAESx128xCBCxSHA256      uint16 = 0x00B2
	cipherxTLSxDHExPSKxWITHxAESx256xCBCxSHA384      uint16 = 0x00B3
	cipherxTLSxDHExPSKxWITHxNULLxSHA256             uint16 = 0x00B4
	cipherxTLSxDHExPSKxWITHxNULLxSHA384             uint16 = 0x00B5
	cipherxTLSxRSAxPSKxWITHxAESx128xCBCxSHA256      uint16 = 0x00B6
	cipherxTLSxRSAxPSKxWITHxAESx256xCBCxSHA384      uint16 = 0x00B7
	cipherxTLSxRSAxPSKxWITHxNULLxSHA256             uint16 = 0x00B8
	cipherxTLSxRSAxPSKxWITHxNULLxSHA384             uint16 = 0x00B9
	cipherxTLSxRSAxWITHxCAMELLIAx128xCBCxSHA256     uint16 = 0x00BA
	cipherxTLSxDHxDSSxWITHxCAMELLIAx128xCBCxSHA256  uint16 = 0x00BB
	cipherxTLSxDHxRSAxWITHxCAMELLIAx128xCBCxSHA256  uint16 = 0x00BC
	cipherxTLSxDHExDSSxWITHxCAMELLIAx128xCBCxSHA256 uint16 = 0x00BD
	cipherxTLSxDHExRSAxWITHxCAMELLIAx128xCBCxSHA256 uint16 = 0x00BE
	cipherxTLSxDHxanonxWITHxCAMELLIAx128xCBCxSHA256 uint16 = 0x00BF
	cipherxTLSxRSAxWITHxCAMELLIAx256xCBCxSHA256     uint16 = 0x00C0
	cipherxTLSxDHxDSSxWITHxCAMELLIAx256xCBCxSHA256  uint16 = 0x00C1
	cipherxTLSxDHxRSAxWITHxCAMELLIAx256xCBCxSHA256  uint16 = 0x00C2
	cipherxTLSxDHExDSSxWITHxCAMELLIAx256xCBCxSHA256 uint16 = 0x00C3
	cipherxTLSxDHExRSAxWITHxCAMELLIAx256xCBCxSHA256 uint16 = 0x00C4
	cipherxTLSxDHxanonxWITHxCAMELLIAx256xCBCxSHA256 uint16 = 0x00C5
	// Unassigned uint16 =  0x00C6-FE
	cipherxTLSxEMPTYxRENEGOTIATIONxINFOxSCSV uint16 = 0x00FF
	// Unassigned uint16 =  0x01-55,*
	cipherxTLSxFALLBACKxSCSV uint16 = 0x5600
	// Unassigned                                   uint16 = 0x5601 - 0xC000
	cipherxTLSxECDHxECDSAxWITHxNULLxSHA                 uint16 = 0xC001
	cipherxTLSxECDHxECDSAxWITHxRC4x128xSHA              uint16 = 0xC002
	cipherxTLSxECDHxECDSAxWITHx3DESxEDExCBCxSHA         uint16 = 0xC003
	cipherxTLSxECDHxECDSAxWITHxAESx128xCBCxSHA          uint16 = 0xC004
	cipherxTLSxECDHxECDSAxWITHxAESx256xCBCxSHA          uint16 = 0xC005
	cipherxTLSxECDHExECDSAxWITHxNULLxSHA                uint16 = 0xC006
	cipherxTLSxECDHExECDSAxWITHxRC4x128xSHA             uint16 = 0xC007
	cipherxTLSxECDHExECDSAxWITHx3DESxEDExCBCxSHA        uint16 = 0xC008
	cipherxTLSxECDHExECDSAxWITHxAESx128xCBCxSHA         uint16 = 0xC009
	cipherxTLSxECDHExECDSAxWITHxAESx256xCBCxSHA         uint16 = 0xC00A
	cipherxTLSxECDHxRSAxWITHxNULLxSHA                   uint16 = 0xC00B
	cipherxTLSxECDHxRSAxWITHxRC4x128xSHA                uint16 = 0xC00C
	cipherxTLSxECDHxRSAxWITHx3DESxEDExCBCxSHA           uint16 = 0xC00D
	cipherxTLSxECDHxRSAxWITHxAESx128xCBCxSHA            uint16 = 0xC00E
	cipherxTLSxECDHxRSAxWITHxAESx256xCBCxSHA            uint16 = 0xC00F
	cipherxTLSxECDHExRSAxWITHxNULLxSHA                  uint16 = 0xC010
	cipherxTLSxECDHExRSAxWITHxRC4x128xSHA               uint16 = 0xC011
	cipherxTLSxECDHExRSAxWITHx3DESxEDExCBCxSHA          uint16 = 0xC012
	cipherxTLSxECDHExRSAxWITHxAESx128xCBCxSHA           uint16 = 0xC013
	cipherxTLSxECDHExRSAxWITHxAESx256xCBCxSHA           uint16 = 0xC014
	cipherxTLSxECDHxanonxWITHxNULLxSHA                  uint16 = 0xC015
	cipherxTLSxECDHxanonxWITHxRC4x128xSHA               uint16 = 0xC016
	cipherxTLSxECDHxanonxWITHx3DESxEDExCBCxSHA          uint16 = 0xC017
	cipherxTLSxECDHxanonxWITHxAESx128xCBCxSHA           uint16 = 0xC018
	cipherxTLSxECDHxanonxWITHxAESx256xCBCxSHA           uint16 = 0xC019
	cipherxTLSxSRPxSHAxWITHx3DESxEDExCBCxSHA            uint16 = 0xC01A
	cipherxTLSxSRPxSHAxRSAxWITHx3DESxEDExCBCxSHA        uint16 = 0xC01B
	cipherxTLSxSRPxSHAxDSSxWITHx3DESxEDExCBCxSHA        uint16 = 0xC01C
	cipherxTLSxSRPxSHAxWITHxAESx128xCBCxSHA             uint16 = 0xC01D
	cipherxTLSxSRPxSHAxRSAxWITHxAESx128xCBCxSHA         uint16 = 0xC01E
	cipherxTLSxSRPxSHAxDSSxWITHxAESx128xCBCxSHA         uint16 = 0xC01F
	cipherxTLSxSRPxSHAxWITHxAESx256xCBCxSHA             uint16 = 0xC020
	cipherxTLSxSRPxSHAxRSAxWITHxAESx256xCBCxSHA         uint16 = 0xC021
	cipherxTLSxSRPxSHAxDSSxWITHxAESx256xCBCxSHA         uint16 = 0xC022
	cipherxTLSxECDHExECDSAxWITHxAESx128xCBCxSHA256      uint16 = 0xC023
	cipherxTLSxECDHExECDSAxWITHxAESx256xCBCxSHA384      uint16 = 0xC024
	cipherxTLSxECDHxECDSAxWITHxAESx128xCBCxSHA256       uint16 = 0xC025
	cipherxTLSxECDHxECDSAxWITHxAESx256xCBCxSHA384       uint16 = 0xC026
	cipherxTLSxECDHExRSAxWITHxAESx128xCBCxSHA256        uint16 = 0xC027
	cipherxTLSxECDHExRSAxWITHxAESx256xCBCxSHA384        uint16 = 0xC028
	cipherxTLSxECDHxRSAxWITHxAESx128xCBCxSHA256         uint16 = 0xC029
	cipherxTLSxECDHxRSAxWITHxAESx256xCBCxSHA384         uint16 = 0xC02A
	cipherxTLSxECDHExECDSAxWITHxAESx128xGCMxSHA256      uint16 = 0xC02B
	cipherxTLSxECDHExECDSAxWITHxAESx256xGCMxSHA384      uint16 = 0xC02C
	cipherxTLSxECDHxECDSAxWITHxAESx128xGCMxSHA256       uint16 = 0xC02D
	cipherxTLSxECDHxECDSAxWITHxAESx256xGCMxSHA384       uint16 = 0xC02E
	cipherxTLSxECDHExRSAxWITHxAESx128xGCMxSHA256        uint16 = 0xC02F
	cipherxTLSxECDHExRSAxWITHxAESx256xGCMxSHA384        uint16 = 0xC030
	cipherxTLSxECDHxRSAxWITHxAESx128xGCMxSHA256         uint16 = 0xC031
	cipherxTLSxECDHxRSAxWITHxAESx256xGCMxSHA384         uint16 = 0xC032
	cipherxTLSxECDHExPSKxWITHxRC4x128xSHA               uint16 = 0xC033
	cipherxTLSxECDHExPSKxWITHx3DESxEDExCBCxSHA          uint16 = 0xC034
	cipherxTLSxECDHExPSKxWITHxAESx128xCBCxSHA           uint16 = 0xC035
	cipherxTLSxECDHExPSKxWITHxAESx256xCBCxSHA           uint16 = 0xC036
	cipherxTLSxECDHExPSKxWITHxAESx128xCBCxSHA256        uint16 = 0xC037
	cipherxTLSxECDHExPSKxWITHxAESx256xCBCxSHA384        uint16 = 0xC038
	cipherxTLSxECDHExPSKxWITHxNULLxSHA                  uint16 = 0xC039
	cipherxTLSxECDHExPSKxWITHxNULLxSHA256               uint16 = 0xC03A
	cipherxTLSxECDHExPSKxWITHxNULLxSHA384               uint16 = 0xC03B
	cipherxTLSxRSAxWITHxARIAx128xCBCxSHA256             uint16 = 0xC03C
	cipherxTLSxRSAxWITHxARIAx256xCBCxSHA384             uint16 = 0xC03D
	cipherxTLSxDHxDSSxWITHxARIAx128xCBCxSHA256          uint16 = 0xC03E
	cipherxTLSxDHxDSSxWITHxARIAx256xCBCxSHA384          uint16 = 0xC03F
	cipherxTLSxDHxRSAxWITHxARIAx128xCBCxSHA256          uint16 = 0xC040
	cipherxTLSxDHxRSAxWITHxARIAx256xCBCxSHA384          uint16 = 0xC041
	cipherxTLSxDHExDSSxWITHxARIAx128xCBCxSHA256         uint16 = 0xC042
	cipherxTLSxDHExDSSxWITHxARIAx256xCBCxSHA384         uint16 = 0xC043
	cipherxTLSxDHExRSAxWITHxARIAx128xCBCxSHA256         uint16 = 0xC044
	cipherxTLSxDHExRSAxWITHxARIAx256xCBCxSHA384         uint16 = 0xC045
	cipherxTLSxDHxanonxWITHxARIAx128xCBCxSHA256         uint16 = 0xC046
	cipherxTLSxDHxanonxWITHxARIAx256xCBCxSHA384         uint16 = 0xC047
	cipherxTLSxECDHExECDSAxWITHxARIAx128xCBCxSHA256     uint16 = 0xC048
	cipherxTLSxECDHExECDSAxWITHxARIAx256xCBCxSHA384     uint16 = 0xC049
	cipherxTLSxECDHxECDSAxWITHxARIAx128xCBCxSHA256      uint16 = 0xC04A
	cipherxTLSxECDHxECDSAxWITHxARIAx256xCBCxSHA384      uint16 = 0xC04B
	cipherxTLSxECDHExRSAxWITHxARIAx128xCBCxSHA256       uint16 = 0xC04C
	cipherxTLSxECDHExRSAxWITHxARIAx256xCBCxSHA384       uint16 = 0xC04D
	cipherxTLSxECDHxRSAxWITHxARIAx128xCBCxSHA256        uint16 = 0xC04E
	cipherxTLSxECDHxRSAxWITHxARIAx256xCBCxSHA384        uint16 = 0xC04F
	cipherxTLSxRSAxWITHxARIAx128xGCMxSHA256             uint16 = 0xC050
	cipherxTLSxRSAxWITHxARIAx256xGCMxSHA384             uint16 = 0xC051
	cipherxTLSxDHExRSAxWITHxARIAx128xGCMxSHA256         uint16 = 0xC052
	cipherxTLSxDHExRSAxWITHxARIAx256xGCMxSHA384         uint16 = 0xC053
	cipherxTLSxDHxRSAxWITHxARIAx128xGCMxSHA256          uint16 = 0xC054
	cipherxTLSxDHxRSAxWITHxARIAx256xGCMxSHA384          uint16 = 0xC055
	cipherxTLSxDHExDSSxWITHxARIAx128xGCMxSHA256         uint16 = 0xC056
	cipherxTLSxDHExDSSxWITHxARIAx256xGCMxSHA384         uint16 = 0xC057
	cipherxTLSxDHxDSSxWITHxARIAx128xGCMxSHA256          uint16 = 0xC058
	cipherxTLSxDHxDSSxWITHxARIAx256xGCMxSHA384          uint16 = 0xC059
	cipherxTLSxDHxanonxWITHxARIAx128xGCMxSHA256         uint16 = 0xC05A
	cipherxTLSxDHxanonxWITHxARIAx256xGCMxSHA384         uint16 = 0xC05B
	cipherxTLSxECDHExECDSAxWITHxARIAx128xGCMxSHA256     uint16 = 0xC05C
	cipherxTLSxECDHExECDSAxWITHxARIAx256xGCMxSHA384     uint16 = 0xC05D
	cipherxTLSxECDHxECDSAxWITHxARIAx128xGCMxSHA256      uint16 = 0xC05E
	cipherxTLSxECDHxECDSAxWITHxARIAx256xGCMxSHA384      uint16 = 0xC05F
	cipherxTLSxECDHExRSAxWITHxARIAx128xGCMxSHA256       uint16 = 0xC060
	cipherxTLSxECDHExRSAxWITHxARIAx256xGCMxSHA384       uint16 = 0xC061
	cipherxTLSxECDHxRSAxWITHxARIAx128xGCMxSHA256        uint16 = 0xC062
	cipherxTLSxECDHxRSAxWITHxARIAx256xGCMxSHA384        uint16 = 0xC063
	cipherxTLSxPSKxWITHxARIAx128xCBCxSHA256             uint16 = 0xC064
	cipherxTLSxPSKxWITHxARIAx256xCBCxSHA384             uint16 = 0xC065
	cipherxTLSxDHExPSKxWITHxARIAx128xCBCxSHA256         uint16 = 0xC066
	cipherxTLSxDHExPSKxWITHxARIAx256xCBCxSHA384         uint16 = 0xC067
	cipherxTLSxRSAxPSKxWITHxARIAx128xCBCxSHA256         uint16 = 0xC068
	cipherxTLSxRSAxPSKxWITHxARIAx256xCBCxSHA384         uint16 = 0xC069
	cipherxTLSxPSKxWITHxARIAx128xGCMxSHA256             uint16 = 0xC06A
	cipherxTLSxPSKxWITHxARIAx256xGCMxSHA384             uint16 = 0xC06B
	cipherxTLSxDHExPSKxWITHxARIAx128xGCMxSHA256         uint16 = 0xC06C
	cipherxTLSxDHExPSKxWITHxARIAx256xGCMxSHA384         uint16 = 0xC06D
	cipherxTLSxRSAxPSKxWITHxARIAx128xGCMxSHA256         uint16 = 0xC06E
	cipherxTLSxRSAxPSKxWITHxARIAx256xGCMxSHA384         uint16 = 0xC06F
	cipherxTLSxECDHExPSKxWITHxARIAx128xCBCxSHA256       uint16 = 0xC070
	cipherxTLSxECDHExPSKxWITHxARIAx256xCBCxSHA384       uint16 = 0xC071
	cipherxTLSxECDHExECDSAxWITHxCAMELLIAx128xCBCxSHA256 uint16 = 0xC072
	cipherxTLSxECDHExECDSAxWITHxCAMELLIAx256xCBCxSHA384 uint16 = 0xC073
	cipherxTLSxECDHxECDSAxWITHxCAMELLIAx128xCBCxSHA256  uint16 = 0xC074
	cipherxTLSxECDHxECDSAxWITHxCAMELLIAx256xCBCxSHA384  uint16 = 0xC075
	cipherxTLSxECDHExRSAxWITHxCAMELLIAx128xCBCxSHA256   uint16 = 0xC076
	cipherxTLSxECDHExRSAxWITHxCAMELLIAx256xCBCxSHA384   uint16 = 0xC077
	cipherxTLSxECDHxRSAxWITHxCAMELLIAx128xCBCxSHA256    uint16 = 0xC078
	cipherxTLSxECDHxRSAxWITHxCAMELLIAx256xCBCxSHA384    uint16 = 0xC079
	cipherxTLSxRSAxWITHxCAMELLIAx128xGCMxSHA256         uint16 = 0xC07A
	cipherxTLSxRSAxWITHxCAMELLIAx256xGCMxSHA384         uint16 = 0xC07B
	cipherxTLSxDHExRSAxWITHxCAMELLIAx128xGCMxSHA256     uint16 = 0xC07C
	cipherxTLSxDHExRSAxWITHxCAMELLIAx256xGCMxSHA384     uint16 = 0xC07D
	cipherxTLSxDHxRSAxWITHxCAMELLIAx128xGCMxSHA256      uint16 = 0xC07E
	cipherxTLSxDHxRSAxWITHxCAMELLIAx256xGCMxSHA384      uint16 = 0xC07F
	cipherxTLSxDHExDSSxWITHxCAMELLIAx128xGCMxSHA256     uint16 = 0xC080
	cipherxTLSxDHExDSSxWITHxCAMELLIAx256xGCMxSHA384     uint16 = 0xC081
	cipherxTLSxDHxDSSxWITHxCAMELLIAx128xGCMxSHA256      uint16 = 0xC082
	cipherxTLSxDHxDSSxWITHxCAMELLIAx256xGCMxSHA384      uint16 = 0xC083
	cipherxTLSxDHxanonxWITHxCAMELLIAx128xGCMxSHA256     uint16 = 0xC084
	cipherxTLSxDHxanonxWITHxCAMELLIAx256xGCMxSHA384     uint16 = 0xC085
	cipherxTLSxECDHExECDSAxWITHxCAMELLIAx128xGCMxSHA256 uint16 = 0xC086
	cipherxTLSxECDHExECDSAxWITHxCAMELLIAx256xGCMxSHA384 uint16 = 0xC087
	cipherxTLSxECDHxECDSAxWITHxCAMELLIAx128xGCMxSHA256  uint16 = 0xC088
	cipherxTLSxECDHxECDSAxWITHxCAMELLIAx256xGCMxSHA384  uint16 = 0xC089
	cipherxTLSxECDHExRSAxWITHxCAMELLIAx128xGCMxSHA256   uint16 = 0xC08A
	cipherxTLSxECDHExRSAxWITHxCAMELLIAx256xGCMxSHA384   uint16 = 0xC08B
	cipherxTLSxECDHxRSAxWITHxCAMELLIAx128xGCMxSHA256    uint16 = 0xC08C
	cipherxTLSxECDHxRSAxWITHxCAMELLIAx256xGCMxSHA384    uint16 = 0xC08D
	cipherxTLSxPSKxWITHxCAMELLIAx128xGCMxSHA256         uint16 = 0xC08E
	cipherxTLSxPSKxWITHxCAMELLIAx256xGCMxSHA384         uint16 = 0xC08F
	cipherxTLSxDHExPSKxWITHxCAMELLIAx128xGCMxSHA256     uint16 = 0xC090
	cipherxTLSxDHExPSKxWITHxCAMELLIAx256xGCMxSHA384     uint16 = 0xC091
	cipherxTLSxRSAxPSKxWITHxCAMELLIAx128xGCMxSHA256     uint16 = 0xC092
	cipherxTLSxRSAxPSKxWITHxCAMELLIAx256xGCMxSHA384     uint16 = 0xC093
	cipherxTLSxPSKxWITHxCAMELLIAx128xCBCxSHA256         uint16 = 0xC094
	cipherxTLSxPSKxWITHxCAMELLIAx256xCBCxSHA384         uint16 = 0xC095
	cipherxTLSxDHExPSKxWITHxCAMELLIAx128xCBCxSHA256     uint16 = 0xC096
	cipherxTLSxDHExPSKxWITHxCAMELLIAx256xCBCxSHA384     uint16 = 0xC097
	cipherxTLSxRSAxPSKxWITHxCAMELLIAx128xCBCxSHA256     uint16 = 0xC098
	cipherxTLSxRSAxPSKxWITHxCAMELLIAx256xCBCxSHA384     uint16 = 0xC099
	cipherxTLSxECDHExPSKxWITHxCAMELLIAx128xCBCxSHA256   uint16 = 0xC09A
	cipherxTLSxECDHExPSKxWITHxCAMELLIAx256xCBCxSHA384   uint16 = 0xC09B
	cipherxTLSxRSAxWITHxAESx128xCCM                     uint16 = 0xC09C
	cipherxTLSxRSAxWITHxAESx256xCCM                     uint16 = 0xC09D
	cipherxTLSxDHExRSAxWITHxAESx128xCCM                 uint16 = 0xC09E
	cipherxTLSxDHExRSAxWITHxAESx256xCCM                 uint16 = 0xC09F
	cipherxTLSxRSAxWITHxAESx128xCCMx8                   uint16 = 0xC0A0
	cipherxTLSxRSAxWITHxAESx256xCCMx8                   uint16 = 0xC0A1
	cipherxTLSxDHExRSAxWITHxAESx128xCCMx8               uint16 = 0xC0A2
	cipherxTLSxDHExRSAxWITHxAESx256xCCMx8               uint16 = 0xC0A3
	cipherxTLSxPSKxWITHxAESx128xCCM                     uint16 = 0xC0A4
	cipherxTLSxPSKxWITHxAESx256xCCM                     uint16 = 0xC0A5
	cipherxTLSxDHExPSKxWITHxAESx128xCCM                 uint16 = 0xC0A6
	cipherxTLSxDHExPSKxWITHxAESx256xCCM                 uint16 = 0xC0A7
	cipherxTLSxPSKxWITHxAESx128xCCMx8                   uint16 = 0xC0A8
	cipherxTLSxPSKxWITHxAESx256xCCMx8                   uint16 = 0xC0A9
	cipherxTLSxPSKxDHExWITHxAESx128xCCMx8               uint16 = 0xC0AA
	cipherxTLSxPSKxDHExWITHxAESx256xCCMx8               uint16 = 0xC0AB
	cipherxTLSxECDHExECDSAxWITHxAESx128xCCM             uint16 = 0xC0AC
	cipherxTLSxECDHExECDSAxWITHxAESx256xCCM             uint16 = 0xC0AD
	cipherxTLSxECDHExECDSAxWITHxAESx128xCCMx8           uint16 = 0xC0AE
	cipherxTLSxECDHExECDSAxWITHxAESx256xCCMx8           uint16 = 0xC0AF
	// Unassigned uint16 =  0xC0B0-FF
	// Unassigned uint16 =  0xC1-CB,*
	// Unassigned uint16 =  0xCC00-A7
	cipherxTLSxECDHExRSAxWITHxCHACHA20xPOLY1305xSHA256   uint16 = 0xCCA8
	cipherxTLSxECDHExECDSAxWITHxCHACHA20xPOLY1305xSHA256 uint16 = 0xCCA9
	cipherxTLSxDHExRSAxWITHxCHACHA20xPOLY1305xSHA256     uint16 = 0xCCAA
	cipherxTLSxPSKxWITHxCHACHA20xPOLY1305xSHA256         uint16 = 0xCCAB
	cipherxTLSxECDHExPSKxWITHxCHACHA20xPOLY1305xSHA256   uint16 = 0xCCAC
	cipherxTLSxDHExPSKxWITHxCHACHA20xPOLY1305xSHA256     uint16 = 0xCCAD
	cipherxTLSxRSAxPSKxWITHxCHACHA20xPOLY1305xSHA256     uint16 = 0xCCAE
)

// isBadCipher reports whether the cipher is blacklisted by the HTTP/2 spec.
// References:
// https://tools.ietf.org/html/rfc7540#appendix-A
// Reject cipher suites from Appendix A.
// "This list includes those cipher suites that do not
// offer an ephemeral key exchange and those that are
// based on the TLS null, stream or block cipher type"
func isBadCipher(cipher uint16) bool {
	switch cipher {
	case cipherxTLSxNULLxWITHxNULLxNULL,
		cipherxTLSxRSAxWITHxNULLxMD5,
		cipherxTLSxRSAxWITHxNULLxSHA,
		cipherxTLSxRSAxEXPORTxWITHxRC4x40xMD5,
		cipherxTLSxRSAxWITHxRC4x128xMD5,
		cipherxTLSxRSAxWITHxRC4x128xSHA,
		cipherxTLSxRSAxEXPORTxWITHxRC2xCBCx40xMD5,
		cipherxTLSxRSAxWITHxIDEAxCBCxSHA,
		cipherxTLSxRSAxEXPORTxWITHxDES40xCBCxSHA,
		cipherxTLSxRSAxWITHxDESxCBCxSHA,
		cipherxTLSxRSAxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxDHxDSSxEXPORTxWITHxDES40xCBCxSHA,
		cipherxTLSxDHxDSSxWITHxDESxCBCxSHA,
		cipherxTLSxDHxDSSxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxDHxRSAxEXPORTxWITHxDES40xCBCxSHA,
		cipherxTLSxDHxRSAxWITHxDESxCBCxSHA,
		cipherxTLSxDHxRSAxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxDHExDSSxEXPORTxWITHxDES40xCBCxSHA,
		cipherxTLSxDHExDSSxWITHxDESxCBCxSHA,
		cipherxTLSxDHExDSSxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxDHExRSAxEXPORTxWITHxDES40xCBCxSHA,
		cipherxTLSxDHExRSAxWITHxDESxCBCxSHA,
		cipherxTLSxDHExRSAxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxDHxanonxEXPORTxWITHxRC4x40xMD5,
		cipherxTLSxDHxanonxWITHxRC4x128xMD5,
		cipherxTLSxDHxanonxEXPORTxWITHxDES40xCBCxSHA,
		cipherxTLSxDHxanonxWITHxDESxCBCxSHA,
		cipherxTLSxDHxanonxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxKRB5xWITHxDESxCBCxSHA,
		cipherxTLSxKRB5xWITHx3DESxEDExCBCxSHA,
		cipherxTLSxKRB5xWITHxRC4x128xSHA,
		cipherxTLSxKRB5xWITHxIDEAxCBCxSHA,
		cipherxTLSxKRB5xWITHxDESxCBCxMD5,
		cipherxTLSxKRB5xWITHx3DESxEDExCBCxMD5,
		cipherxTLSxKRB5xWITHxRC4x128xMD5,
		cipherxTLSxKRB5xWITHxIDEAxCBCxMD5,
		cipherxTLSxKRB5xEXPORTxWITHxDESxCBCx40xSHA,
		cipherxTLSxKRB5xEXPORTxWITHxRC2xCBCx40xSHA,
		cipherxTLSxKRB5xEXPORTxWITHxRC4x40xSHA,
		cipherxTLSxKRB5xEXPORTxWITHxDESxCBCx40xMD5,
		cipherxTLSxKRB5xEXPORTxWITHxRC2xCBCx40xMD5,
		cipherxTLSxKRB5xEXPORTxWITHxRC4x40xMD5,
		cipherxTLSxPSKxWITHxNULLxSHA,
		cipherxTLSxDHExPSKxWITHxNULLxSHA,
		cipherxTLSxRSAxPSKxWITHxNULLxSHA,
		cipherxTLSxRSAxWITHxAESx128xCBCxSHA,
		cipherxTLSxDHxDSSxWITHxAESx128xCBCxSHA,
		cipherxTLSxDHxRSAxWITHxAESx128xCBCxSHA,
		cipherxTLSxDHExDSSxWITHxAESx128xCBCxSHA,
		cipherxTLSxDHExRSAxWITHxAESx128xCBCxSHA,
		cipherxTLSxDHxanonxWITHxAESx128xCBCxSHA,
		cipherxTLSxRSAxWITHxAESx256xCBCxSHA,
		cipherxTLSxDHxDSSxWITHxAESx256xCBCxSHA,
		cipherxTLSxDHxRSAxWITHxAESx256xCBCxSHA,
		cipherxTLSxDHExDSSxWITHxAESx256xCBCxSHA,
		cipherxTLSxDHExRSAxWITHxAESx256xCBCxSHA,
		cipherxTLSxDHxanonxWITHxAESx256xCBCxSHA,
		cipherxTLSxRSAxWITHxNULLxSHA256,
		cipherxTLSxRSAxWITHxAESx128xCBCxSHA256,
		cipherxTLSxRSAxWITHxAESx256xCBCxSHA256,
		cipherxTLSxDHxDSSxWITHxAESx128xCBCxSHA256,
		cipherxTLSxDHxRSAxWITHxAESx128xCBCxSHA256,
		cipherxTLSxDHExDSSxWITHxAESx128xCBCxSHA256,
		cipherxTLSxRSAxWITHxCAMELLIAx128xCBCxSHA,
		cipherxTLSxDHxDSSxWITHxCAMELLIAx128xCBCxSHA,
		cipherxTLSxDHxRSAxWITHxCAMELLIAx128xCBCxSHA,
		cipherxTLSxDHExDSSxWITHxCAMELLIAx128xCBCxSHA,
		cipherxTLSxDHExRSAxWITHxCAMELLIAx128xCBCxSHA,
		cipherxTLSxDHxanonxWITHxCAMELLIAx128xCBCxSHA,
		cipherxTLSxDHExRSAxWITHxAESx128xCBCxSHA256,
		cipherxTLSxDHxDSSxWITHxAESx256xCBCxSHA256,
		cipherxTLSxDHxRSAxWITHxAESx256xCBCxSHA256,
		cipherxTLSxDHExDSSxWITHxAESx256xCBCxSHA256,
		cipherxTLSxDHExRSAxWITHxAESx256xCBCxSHA256,
		cipherxTLSxDHxanonxWITHxAESx128xCBCxSHA256,
		cipherxTLSxDHxanonxWITHxAESx256xCBCxSHA256,
		cipherxTLSxRSAxWITHxCAMELLIAx256xCBCxSHA,
		cipherxTLSxDHxDSSxWITHxCAMELLIAx256xCBCxSHA,
		cipherxTLSxDHxRSAxWITHxCAMELLIAx256xCBCxSHA,
		cipherxTLSxDHExDSSxWITHxCAMELLIAx256xCBCxSHA,
		cipherxTLSxDHExRSAxWITHxCAMELLIAx256xCBCxSHA,
		cipherxTLSxDHxanonxWITHxCAMELLIAx256xCBCxSHA,
		cipherxTLSxPSKxWITHxRC4x128xSHA,
		cipherxTLSxPSKxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxPSKxWITHxAESx128xCBCxSHA,
		cipherxTLSxPSKxWITHxAESx256xCBCxSHA,
		cipherxTLSxDHExPSKxWITHxRC4x128xSHA,
		cipherxTLSxDHExPSKxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxDHExPSKxWITHxAESx128xCBCxSHA,
		cipherxTLSxDHExPSKxWITHxAESx256xCBCxSHA,
		cipherxTLSxRSAxPSKxWITHxRC4x128xSHA,
		cipherxTLSxRSAxPSKxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxRSAxPSKxWITHxAESx128xCBCxSHA,
		cipherxTLSxRSAxPSKxWITHxAESx256xCBCxSHA,
		cipherxTLSxRSAxWITHxSEEDxCBCxSHA,
		cipherxTLSxDHxDSSxWITHxSEEDxCBCxSHA,
		cipherxTLSxDHxRSAxWITHxSEEDxCBCxSHA,
		cipherxTLSxDHExDSSxWITHxSEEDxCBCxSHA,
		cipherxTLSxDHExRSAxWITHxSEEDxCBCxSHA,
		cipherxTLSxDHxanonxWITHxSEEDxCBCxSHA,
		cipherxTLSxRSAxWITHxAESx128xGCMxSHA256,
		cipherxTLSxRSAxWITHxAESx256xGCMxSHA384,
		cipherxTLSxDHxRSAxWITHxAESx128xGCMxSHA256,
		cipherxTLSxDHxRSAxWITHxAESx256xGCMxSHA384,
		cipherxTLSxDHxDSSxWITHxAESx128xGCMxSHA256,
		cipherxTLSxDHxDSSxWITHxAESx256xGCMxSHA384,
		cipherxTLSxDHxanonxWITHxAESx128xGCMxSHA256,
		cipherxTLSxDHxanonxWITHxAESx256xGCMxSHA384,
		cipherxTLSxPSKxWITHxAESx128xGCMxSHA256,
		cipherxTLSxPSKxWITHxAESx256xGCMxSHA384,
		cipherxTLSxRSAxPSKxWITHxAESx128xGCMxSHA256,
		cipherxTLSxRSAxPSKxWITHxAESx256xGCMxSHA384,
		cipherxTLSxPSKxWITHxAESx128xCBCxSHA256,
		cipherxTLSxPSKxWITHxAESx256xCBCxSHA384,
		cipherxTLSxPSKxWITHxNULLxSHA256,
		cipherxTLSxPSKxWITHxNULLxSHA384,
		cipherxTLSxDHExPSKxWITHxAESx128xCBCxSHA256,
		cipherxTLSxDHExPSKxWITHxAESx256xCBCxSHA384,
		cipherxTLSxDHExPSKxWITHxNULLxSHA256,
		cipherxTLSxDHExPSKxWITHxNULLxSHA384,
		cipherxTLSxRSAxPSKxWITHxAESx128xCBCxSHA256,
		cipherxTLSxRSAxPSKxWITHxAESx256xCBCxSHA384,
		cipherxTLSxRSAxPSKxWITHxNULLxSHA256,
		cipherxTLSxRSAxPSKxWITHxNULLxSHA384,
		cipherxTLSxRSAxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxDHxDSSxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxDHxRSAxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxDHExDSSxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxDHExRSAxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxDHxanonxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxRSAxWITHxCAMELLIAx256xCBCxSHA256,
		cipherxTLSxDHxDSSxWITHxCAMELLIAx256xCBCxSHA256,
		cipherxTLSxDHxRSAxWITHxCAMELLIAx256xCBCxSHA256,
		cipherxTLSxDHExDSSxWITHxCAMELLIAx256xCBCxSHA256,
		cipherxTLSxDHExRSAxWITHxCAMELLIAx256xCBCxSHA256,
		cipherxTLSxDHxanonxWITHxCAMELLIAx256xCBCxSHA256,
		cipherxTLSxEMPTYxRENEGOTIATIONxINFOxSCSV,
		cipherxTLSxECDHxECDSAxWITHxNULLxSHA,
		cipherxTLSxECDHxECDSAxWITHxRC4x128xSHA,
		cipherxTLSxECDHxECDSAxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxECDHxECDSAxWITHxAESx128xCBCxSHA,
		cipherxTLSxECDHxECDSAxWITHxAESx256xCBCxSHA,
		cipherxTLSxECDHExECDSAxWITHxNULLxSHA,
		cipherxTLSxECDHExECDSAxWITHxRC4x128xSHA,
		cipherxTLSxECDHExECDSAxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxECDHExECDSAxWITHxAESx128xCBCxSHA,
		cipherxTLSxECDHExECDSAxWITHxAESx256xCBCxSHA,
		cipherxTLSxECDHxRSAxWITHxNULLxSHA,
		cipherxTLSxECDHxRSAxWITHxRC4x128xSHA,
		cipherxTLSxECDHxRSAxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxECDHxRSAxWITHxAESx128xCBCxSHA,
		cipherxTLSxECDHxRSAxWITHxAESx256xCBCxSHA,
		cipherxTLSxECDHExRSAxWITHxNULLxSHA,
		cipherxTLSxECDHExRSAxWITHxRC4x128xSHA,
		cipherxTLSxECDHExRSAxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxECDHExRSAxWITHxAESx128xCBCxSHA,
		cipherxTLSxECDHExRSAxWITHxAESx256xCBCxSHA,
		cipherxTLSxECDHxanonxWITHxNULLxSHA,
		cipherxTLSxECDHxanonxWITHxRC4x128xSHA,
		cipherxTLSxECDHxanonxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxECDHxanonxWITHxAESx128xCBCxSHA,
		cipherxTLSxECDHxanonxWITHxAESx256xCBCxSHA,
		cipherxTLSxSRPxSHAxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxSRPxSHAxRSAxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxSRPxSHAxDSSxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxSRPxSHAxWITHxAESx128xCBCxSHA,
		cipherxTLSxSRPxSHAxRSAxWITHxAESx128xCBCxSHA,
		cipherxTLSxSRPxSHAxDSSxWITHxAESx128xCBCxSHA,
		cipherxTLSxSRPxSHAxWITHxAESx256xCBCxSHA,
		cipherxTLSxSRPxSHAxRSAxWITHxAESx256xCBCxSHA,
		cipherxTLSxSRPxSHAxDSSxWITHxAESx256xCBCxSHA,
		cipherxTLSxECDHExECDSAxWITHxAESx128xCBCxSHA256,
		cipherxTLSxECDHExECDSAxWITHxAESx256xCBCxSHA384,
		cipherxTLSxECDHxECDSAxWITHxAESx128xCBCxSHA256,
		cipherxTLSxECDHxECDSAxWITHxAESx256xCBCxSHA384,
		cipherxTLSxECDHExRSAxWITHxAESx128xCBCxSHA256,
		cipherxTLSxECDHExRSAxWITHxAESx256xCBCxSHA384,
		cipherxTLSxECDHxRSAxWITHxAESx128xCBCxSHA256,
		cipherxTLSxECDHxRSAxWITHxAESx256xCBCxSHA384,
		cipherxTLSxECDHxECDSAxWITHxAESx128xGCMxSHA256,
		cipherxTLSxECDHxECDSAxWITHxAESx256xGCMxSHA384,
		cipherxTLSxECDHxRSAxWITHxAESx128xGCMxSHA256,
		cipherxTLSxECDHxRSAxWITHxAESx256xGCMxSHA384,
		cipherxTLSxECDHExPSKxWITHxRC4x128xSHA,
		cipherxTLSxECDHExPSKxWITHx3DESxEDExCBCxSHA,
		cipherxTLSxECDHExPSKxWITHxAESx128xCBCxSHA,
		cipherxTLSxECDHExPSKxWITHxAESx256xCBCxSHA,
		cipherxTLSxECDHExPSKxWITHxAESx128xCBCxSHA256,
		cipherxTLSxECDHExPSKxWITHxAESx256xCBCxSHA384,
		cipherxTLSxECDHExPSKxWITHxNULLxSHA,
		cipherxTLSxECDHExPSKxWITHxNULLxSHA256,
		cipherxTLSxECDHExPSKxWITHxNULLxSHA384,
		cipherxTLSxRSAxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxRSAxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxDHxDSSxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxDHxDSSxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxDHxRSAxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxDHxRSAxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxDHExDSSxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxDHExDSSxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxDHExRSAxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxDHExRSAxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxDHxanonxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxDHxanonxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxECDHExECDSAxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxECDHExECDSAxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxECDHxECDSAxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxECDHxECDSAxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxECDHExRSAxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxECDHExRSAxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxECDHxRSAxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxECDHxRSAxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxRSAxWITHxARIAx128xGCMxSHA256,
		cipherxTLSxRSAxWITHxARIAx256xGCMxSHA384,
		cipherxTLSxDHxRSAxWITHxARIAx128xGCMxSHA256,
		cipherxTLSxDHxRSAxWITHxARIAx256xGCMxSHA384,
		cipherxTLSxDHxDSSxWITHxARIAx128xGCMxSHA256,
		cipherxTLSxDHxDSSxWITHxARIAx256xGCMxSHA384,
		cipherxTLSxDHxanonxWITHxARIAx128xGCMxSHA256,
		cipherxTLSxDHxanonxWITHxARIAx256xGCMxSHA384,
		cipherxTLSxECDHxECDSAxWITHxARIAx128xGCMxSHA256,
		cipherxTLSxECDHxECDSAxWITHxARIAx256xGCMxSHA384,
		cipherxTLSxECDHxRSAxWITHxARIAx128xGCMxSHA256,
		cipherxTLSxECDHxRSAxWITHxARIAx256xGCMxSHA384,
		cipherxTLSxPSKxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxPSKxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxDHExPSKxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxDHExPSKxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxRSAxPSKxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxRSAxPSKxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxPSKxWITHxARIAx128xGCMxSHA256,
		cipherxTLSxPSKxWITHxARIAx256xGCMxSHA384,
		cipherxTLSxRSAxPSKxWITHxARIAx128xGCMxSHA256,
		cipherxTLSxRSAxPSKxWITHxARIAx256xGCMxSHA384,
		cipherxTLSxECDHExPSKxWITHxARIAx128xCBCxSHA256,
		cipherxTLSxECDHExPSKxWITHxARIAx256xCBCxSHA384,
		cipherxTLSxECDHExECDSAxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxECDHExECDSAxWITHxCAMELLIAx256xCBCxSHA384,
		cipherxTLSxECDHxECDSAxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxECDHxECDSAxWITHxCAMELLIAx256xCBCxSHA384,
		cipherxTLSxECDHExRSAxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxECDHExRSAxWITHxCAMELLIAx256xCBCxSHA384,
		cipherxTLSxECDHxRSAxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxECDHxRSAxWITHxCAMELLIAx256xCBCxSHA384,
		cipherxTLSxRSAxWITHxCAMELLIAx128xGCMxSHA256,
		cipherxTLSxRSAxWITHxCAMELLIAx256xGCMxSHA384,
		cipherxTLSxDHxRSAxWITHxCAMELLIAx128xGCMxSHA256,
		cipherxTLSxDHxRSAxWITHxCAMELLIAx256xGCMxSHA384,
		cipherxTLSxDHxDSSxWITHxCAMELLIAx128xGCMxSHA256,
		cipherxTLSxDHxDSSxWITHxCAMELLIAx256xGCMxSHA384,
		cipherxTLSxDHxanonxWITHxCAMELLIAx128xGCMxSHA256,
		cipherxTLSxDHxanonxWITHxCAMELLIAx256xGCMxSHA384,
		cipherxTLSxECDHxECDSAxWITHxCAMELLIAx128xGCMxSHA256,
		cipherxTLSxECDHxECDSAxWITHxCAMELLIAx256xGCMxSHA384,
		cipherxTLSxECDHxRSAxWITHxCAMELLIAx128xGCMxSHA256,
		cipherxTLSxECDHxRSAxWITHxCAMELLIAx256xGCMxSHA384,
		cipherxTLSxPSKxWITHxCAMELLIAx128xGCMxSHA256,
		cipherxTLSxPSKxWITHxCAMELLIAx256xGCMxSHA384,
		cipherxTLSxRSAxPSKxWITHxCAMELLIAx128xGCMxSHA256,
		cipherxTLSxRSAxPSKxWITHxCAMELLIAx256xGCMxSHA384,
		cipherxTLSxPSKxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxPSKxWITHxCAMELLIAx256xCBCxSHA384,
		cipherxTLSxDHExPSKxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxDHExPSKxWITHxCAMELLIAx256xCBCxSHA384,
		cipherxTLSxRSAxPSKxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxRSAxPSKxWITHxCAMELLIAx256xCBCxSHA384,
		cipherxTLSxECDHExPSKxWITHxCAMELLIAx128xCBCxSHA256,
		cipherxTLSxECDHExPSKxWITHxCAMELLIAx256xCBCxSHA384,
		cipherxTLSxRSAxWITHxAESx128xCCM,
		cipherxTLSxRSAxWITHxAESx256xCCM,
		cipherxTLSxRSAxWITHxAESx128xCCMx8,
		cipherxTLSxRSAxWITHxAESx256xCCMx8,
		cipherxTLSxPSKxWITHxAESx128xCCM,
		cipherxTLSxPSKxWITHxAESx256xCCM,
		cipherxTLSxPSKxWITHxAESx128xCCMx8,
		cipherxTLSxPSKxWITHxAESx256xCCMx8:
		return true
	default:
		return false
	}
}
