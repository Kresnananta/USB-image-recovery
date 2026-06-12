# USB Image Recovery

Program CLI Python untuk memulihkan gambar dari USB FAT32/exFAT dengan teknik
**file carving**. Sumber dibuka dalam mode read-only dan hasil wajib disimpan ke
drive lain.

Format yang didukung:

- JPEG (`.jpg`)
- PNG (`.png`)
- GIF (`.gif`)
- BMP (`.bmp`)
- WebP (`.webp`)
- TIFF (`.tiff`)

## Batasan penting

File carving mencari struktur gambar di seluruh data mentah. Karena itu:

- gambar yang belum terhapus dapat ikut ditemukan;
- file terhapus yang sudah tertimpa tidak dapat dipulihkan;
- file yang terfragmentasi mungkin gagal atau hanya pulih sebagian;
- nama file, folder, dan waktu asli tidak dapat dikembalikan.

Segera hentikan penggunaan USB setelah file terhapus. Jangan memasang aplikasi,
menyalin file, atau menyimpan hasil recovery ke USB tersebut.

## Persyaratan

- Python 3.10 atau lebih baru
- Tidak memerlukan package eksternal
- Administrator pada Windows atau akses root pada Linux untuk membaca device

## Windows

Lihat USB yang terdeteksi:

```powershell
python .\usb_image_recovery.py --list
```

Buka PowerShell **Run as Administrator**, lalu pindai misalnya drive `E:`:

```powershell
python .\usb_image_recovery.py \\.\E: -o C:\Recovered-USB
```

Program menangani persyaratan sector-aligned I/O milik raw volume Windows secara
otomatis. Karena itu, gunakan path device `\\.\E:` dan bukan hanya `E:\`.

Uji kandidat tanpa menulis file:

```powershell
python .\usb_image_recovery.py \\.\E: --dry-run
```

## Linux

Lihat USB yang terdeteksi:

```bash
python3 usb_image_recovery.py --list
```

Unmount partisi USB terlebih dahulu untuk mencegah perubahan data, kemudian:

```bash
sudo umount /dev/sdb1
sudo python3 usb_image_recovery.py /dev/sdb1 -o "$HOME/Recovered-USB"
```

Pastikan nama device benar dengan `lsblk`. Salah memilih device tidak akan
ditulisi oleh program ini, tetapi pemindaian dapat memakan waktu lama.

## Disk image (lebih aman)

Jika memungkinkan, buat image USB terlebih dahulu dengan alat seperti `ddrescue`,
kemudian pindai image tersebut tanpa hak Administrator/root:

```bash
python3 usb_image_recovery.py usb.img -o ./recovered
```

## Opsi berguna

Hanya pindai format tertentu:

```bash
python3 usb_image_recovery.py usb.img -o recovered --formats jpg,png,webp
```

Batasi ukuran file dan area pemindaian:

```bash
python3 usb_image_recovery.py usb.img -o recovered \
  --max-file-mib 100 --scan-mib 2048
```

Tampilkan bantuan lengkap:

```bash
python3 usb_image_recovery.py --help
```

Untuk melihat alasan kandidat signature ditolak:

```powershell
python .\usb_image_recovery.py \\.\E: --dry-run --formats jpg,png --verbose
```

Nama hasil memuat nomor urut, format, offset asal, dan potongan SHA-256. File
identik dilewati secara default; gunakan `--keep-duplicates` untuk menyimpan
semuanya.

## Menjalankan tes

```bash
python -m unittest -v
```
