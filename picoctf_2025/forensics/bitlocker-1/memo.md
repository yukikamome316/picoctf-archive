# Bitlocker-1

Kali Linux にて以下のコマンドを実行する。

```bash
$ bitlocker2john -i bitlocker-1.dd > ~/Desktop/picoctf/bitlocker.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt ~/Desktop/picoctf/bitlocker.hash

Note: This format may emit false positives, so it will keep trying even after finding a possible candidate.
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (BitLocker, BitLocker [SHA-256 AES 32/64])
Cost 1 (iteration count) is 1048576 for all loaded hashes
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
jacqueline       (?)
jacqueline       (?)
```

後は以下の記事の通りに `/mnt/bitlocker` にマウントする。

<https://qiita.com/momoto/items/f4118c34724ac56e5b79>

```bash
$ sudo dislocker -v -V bitlocker-1.dd -ujacqueline -- /mnt/bitlocker/
$ sudo mount -o loop,ro /mnt/bitlocker/dislocker-file /mnt/bitlocker
$ ls
'$RECYCLE.BIN'  'System Volume Information'   flag.txt
```
