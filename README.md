### KDBX — KeepPass File Format

> KeePass Password Safe is a free and open-source password manager primarily for Windows. It officially supports macOS and Linux operating systems through the use of Mono. Additionally, there are several unofficial ports for Windows Phone, Android, iOS, and BlackBerry devices. KeePass stores usernames, passwords, and other fields, including free-form notes and file attachments, in an encrypted file. This file can be protected by a master password, keyfile, and/or the current Windows account details. By default, the KeePass database is stored on a local file system (as opposed to cloud storage).
>
> — https://en.wikipedia.org/wiki/KeePass

![fileformat](screenshot.png)

ID     | DataType | Header Name           | Description
-------|----------|-----------------------|------------
`0x00` | `[]byte` | `EndHeader`           | defines the end limit for the headers block
