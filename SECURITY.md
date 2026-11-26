# Security Policy / Kebijakan Keamanan

## Melaporkan kerentanan / Reporting a vulnerability

**ID:** Mohon **jangan** membuka issue publik untuk kerentanan. Gunakan fitur
*"Report a vulnerability"* (GitHub Private Vulnerability Reporting) di tab **Security** repositori ini
atau kirim e-mail ke `m.naufalhadyaj@gmail.com`.
Kami berusaha membalas dalam **7 hari** dan menyiapkan perbaikan dalam **90 hari** (lebih cepat untuk
masalah berat). Kredit diberikan di CHANGELOG jika Anda berkenan.

**EN:** Please do **not** open public issues for vulnerabilities. Use GitHub's *"Report a vulnerability"*
(Security tab) or e-mail the address above. Target: acknowledgement within 7 days, fix within 90 days.

> Jangan melampirkan data pasien asli pada laporan. / Never attach real patient data to a report.

## Versi yang didukung / Supported versions

Hanya rilis minor terbaru yang menerima perbaikan keamanan. / Only the latest minor release is patched.

## Model ancaman singkat / Threat model

Alat ini dirancang untuk **pengembangan dan debugging** di mesin/server yang Anda percaya:

| Aset | Perlindungan bawaan | Tanggung jawab Anda |
| :--- | :--- | :--- |
| Token/secret OAuth | Tidak pernah ditulis ke log (header tidak disimpan; field/teks secret disensor) | Jangan menaruh secret di URL/query |
| Data pasien dalam log | Masking PII (`auto` di production), file 0600, retensi 14 hari, batas ukuran | Perlakukan folder log sebagai **data kesehatan** (UU PDP No. 27/2022); enkripsi disk; akses terbatas |
| Port proxy | Hanya loopback secara default; tanpa autentikasi | Jangan diekspos ke jaringan; gunakan firewall/tunnel jika terpaksa |
| Hop SIMRS → proxy | HTTP polos (loopback) | Jangan lintas mesin tanpa TLS tunnel (mis. SSH/WireGuard) |
| Sisi upstream | TLS diverifikasi; `--insecure` ditolak untuk production | — |

**Di luar cakupan:** serangan oleh pengguna lokal ber-root, kompromi OS/Python, kebocoran lewat teks
bebas (catatan klinis) yang tidak dapat dikenali regex masking, dan penggunaan proxy di jaringan tidak tepercaya.
