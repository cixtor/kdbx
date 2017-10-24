package kdbx

import (
	"encoding/binary"
)

// KDBX defines the main library data structure.
//
// KeePass Password Safe is a free and open-source password manager primarily
// for Windows. It officially supports macOS and Linux operating systems
// through the use of Mono. Additionally, there are several unofficial ports
// for Windows Phone, Android, iOS, and BlackBerry devices. KeePass stores
// usernames, passwords, and other fields, including free-form notes and file
// attachments, in an encrypted file. This file can be protected by a master
// password, keyfile, and/or the current Windows account details. By default,
// the KeePass database is stored on a local file system (as opposed to cloud
// storage).
//
// Ref: https://en.wikipedia.org/wiki/KeePass
//
// 0000:  03 d9 a2 9a 67 fb 4b b5  01 00 03 00 02 10 00 31  |....g.K........1|
// 0010:  c1 f2 e6 bf 71 43 50 be  58 05 21 6a fc 5a ff 03  |....qCP.X.!j.Z..|
// 0020:  04 00 01 00 00 00 04 20  00 e1 0e 5b a9 47 c7 dc  |....... ...[.G..|
// 0030:  51 86 b9 fb f1 4d 6a 6d  af 37 09 2d 97 e3 f1 ec  |Q....Mjm.7.-....|
// 0040:  a4 88 8b 8e 17 59 65 aa  56 07 10 00 04 38 8b 41  |.....Ye.V....8.A|
// 0050:  2d 0d 96 e9 ed 21 6d 5e  1e 45 68 0c 05 20 00 bc  |-....!m^.Eh.. ..|
// 0060:  42 4c 8d 6c b5 40 1d c8  9e ba 27 68 3f ef ef 55  |BL.l.@....'h?..U|
// 0070:  a5 e8 aa 77 4c 83 72 07  25 55 27 f7 f8 79 e8 06  |...wL.r.%U'..y..|
// 0080:  08 00 60 ea 00 00 00 00  00 00 08 20 00 a2 60 65  |..`........ ..`e|
// 0090:  6e bc 67 5b 44 15 4c d8  4d d1 eb 39 6c a0 2f 99  |n.g[D.L.M..9l./.|
// 00a0:  66 79 5c 80 95 fa b6 95  13 5e 7e 1d 23 09 20 00  |fy\......^~.#. .|
// 00b0:  6e 59 a8 c2 12 d6 d9 fa  b5 40 9b de 9d 10 4a 2e  |nY.......@....J.|
// 00c0:  74 ce 72 43 95 6d aa 0e  19 25 e4 9b c8 94 e7 bd  |t.rC.m...%......|
// 00d0:  0a 04 00 02 00 00 00 00  04 00 0d 0a 0d 0a        |..............|
type KDBX struct {
	headers []Header
}

// Header defines the KDBX file header.
type Header struct {
	id     uint8
	length uint16
	data   []byte
}

func New() *KDBX {
	return &KDBX{}
}

// EndHeader defines the end limit for the headers block.
func (k *KDBX) EndHeader() []byte {
	return k.headers[0x00].data
}

// Comment is current ignored by KeePass and alternate apps.
func (k *KDBX) Comment() []byte {
	return k.headers[0x01].data
}

// CipherID represents the UUID of the cipher algorithm.
//
// The default cipher is AES-CBC with PKCS7 padding.
func (k *KDBX) CipherID() []byte {
	return k.headers[0x02].data
}
