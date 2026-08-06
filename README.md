# KNU-MAL

Framework riset thesis untuk deteksi Broken Access Control (BAC) kelas MALIS
(Manipulation of Authorization Logic through Identity Substitution) secara
black-box, dari traffic HTTP hasil capture proxy (Burp Suite), menggabungkan
rule deterministik dengan analisis semantik LLM (Qwen2.5:3B via Ollama).

## Alur Kerja (5 Fase)

0. **Nyalakan Burp Suite** — aktifkan proxy listener, arahkan browser (Playwright) untuk lewat proxy tersebut.
1. **knumal-0-browser.py** — bootstrap capture traffic via browser + proxy (Playwright), traffic tercatat di Burp Suite Proxy History.
2. **Export dari Burp Suite** — buka tab **Proxy > HTTP history**, **select all**, klik kanan → **Save items**, pastikan opsi **"Base64-encode requests and responses"** DICENTANG, simpan sebagai file XML.
3. **knumal-1-read-xml.py** — parsing hasil export XML Burp Suite tadi menjadi JSON, hitung hash request (`knumal_req`) dan hash response (`knumal_resp`).
4. **knumal-2-poc-candidate.py** — kelompokkan traffic per user/session/domain menjadi struktur candidate untuk lookup response-similarity.
5. **knumal-3-baseline.py** — replay tiap request di bawah sesi resminya (know-normal baseline), klasifikasi endpoint `simple` (response stabil) atau `ambiguous` (response mengandung field volatile).
6. **knumal-att4ck.py** — jalankan simulasi serangan (Anonymous Access, Session Swapping, Parameter Mutation) dan validasi hasil, memuat modul di `knumal_att4ck_modul/` secara dinamis.

## Struktur Modul

- `knumal_att4ck_modul/simple/` — oracle deterministik (hash-match, status-code, Jaccard structural similarity) untuk endpoint `classification=simple`.
- `knumal_att4ck_modul/ambiguous/` — oracle semantik untuk endpoint `classification=ambiguous`:
  - `anonym_and_session_swap/` — triase LLM (skor similarity 0–100) untuk Anonymous & Session Swapping.
  - `parameter_mutation_fuzzing/` — Stage 1 structural pre-check, Stage 2 LLM men-discover field identitas dari baseline lalu heuristik Python membandingkan field yang berubah.
- `tools/llm_classifier.py` — wrapper pemanggilan Ollama (`call_ollama`), dipakai oleh kedua modul `ambiguous/`.
- `model_read_xml.py` — parser body request (JSON/form) dipakai `knumal-1-read-xml.py`.

## Instalasi

```bash
pip install -r requirements.txt
playwright install chromium
```

### Ollama + Model LLM

```bash
brew install ollama       # atau lihat ollama.com untuk OS lain
ollama serve              # jalankan server (default: localhost:11434)
ollama pull qwen2.5:3b    # model yang dipakai seluruh modul ambiguous/
```

## Menjalankan

```bash
# 0. Nyalakan Burp Suite (proxy listener aktif) sebelum capture
python3 knumal-0-browser.py
# -> di Burp Suite: Proxy > HTTP history > select all > klik kanan > Save items
#    (centang "Base64-encode requests and responses") -> simpan sebagai .xml
python3 knumal-1-read-xml.py
python3 knumal-2-poc-candidate.py
python3 knumal-3-baseline.py
python3 knumal-att4ck.py
```
