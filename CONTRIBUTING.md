# Kontribusi / Contributing

Terima kasih sudah ingin berkontribusi! / Thanks for contributing!

## Aturan penting: tidak ada data pasien
**Jangan pernah** menyertakan log, payload, screenshot, atau NIK/nama pasien **asli** pada issue, PR, atau test.
Gunakan data dummy. PR yang memuat data kesehatan asli akan ditutup dan riwayatnya perlu dibersihkan.

## Menjalankan test dan pemindaian
```bash
python3 -m unittest discover -s tests -t .       # test (hanya stdlib)
pip install bandit pyflakes && bandit -r src && python3 -m pyflakes src tests
```
CI menjalankan hal yang sama di Python 3.10-3.13.

## Pedoman kode
- Hanya **standard library** - jangan menambah dependensi tanpa diskusi di issue.
- Perubahan perilaku keamanan (masking, permission, validasi input, proxy) **wajib** disertai test.
- Jangan mengubah isi request/response yang diteruskan ke upstream; sanitasi hanya berlaku pada **log**.
- Pesan commit singkat dan jelas; perbarui `CHANGELOG.md`.

## Alur
1. Fork, buat branch, lakukan perubahan + test.
2. Pastikan test, Bandit, dan pyflakes bersih.
3. Buka PR yang menjelaskan *apa* dan *mengapa*.

Dengan berkontribusi, Anda setuju kontribusi dilisensikan di bawah lisensi MIT proyek ini.
