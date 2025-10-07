# 🔒 Secure Data Manager

Ett säkert krypterings- och designsystem med tre självständiga program byggda i Rust.

## 📦 Programmen

### 1. 🔐 AI_databasen
**Krypterar och dekrypterar känslig data med lösenordsskydd**

#### Funktioner:
- ✅ Läser från `filer` (klartext) och bilder konverteras till Base64  och krypteras.
- ✅ Krypterar med AEAD (AES-256-GCM) + Argon2id key derivation (128MB, 4 iter)
- ✅ **Lösenordsverifiering** - Hash:en sparas i krypterad data
- ✅ **Flera kategorier** - Stödjer flera ID:n i samma personer2-fil
- ✅ **Brute-force-skydd** - Max 5 försök, 15 min lockout, persistent i filen
- ✅ **Återstående försök** - Visar "4 försök kvar", "3 försök kvar" osv.
- ✅ **Bildstöd** - Visar bilder som konverterats till Base64 i tabellen
- ✅ Sorterbara kolumner med klickbara headers (▲/▼)
- ✅ **Dynamiska kolumnnamn** - Kolumn1, Kolumn2, Kolumn3 osv.
- ✅ Alignerade kolumner i Grid-layout
- ✅ Läser tema från `desig.yaml`

#### Användning:
```bash
./AI_databasen
```

**I GUI:**
1. Fyll i **ID** (identifieringskod, t.ex. "personal", "projekt", "kunder")
2. Fyll i **Lösenord** 
3. Klicka **"Kryptera & Kopiera"** 
   - Läser `filer` → krypterar → lägger till/uppdaterar i `personer.bin`
   - Flera ID:n kan finnas samtidigt!
4. Klicka **"Visa"** 
   - Dekrypterar och verifierar lösenord
   - Visar data i sorterad tabell
   - Felmeddelande om fel lösenord!
5. Klicka på kolumnrubriker för att sortera (↑/↓)

### 2. 🎨 aiagent_design
**Visuellt designverktyg för att skapa teman**

#### Funktioner:
- ✨ **Två arbetslägen:**
  - **📝 Prompt-läge** - Skriv fri text ("mörk blå", "ljus grön")
  - **🎨 Färgväljare** - Grafiska RGB-skjutreglage med live-förhandsvisning
- 🖼️ **Stora färgrutor** - Se exakt hur färgerna ser ut
- 📊 **Text-på-bakgrund preview** - Kontrollera kontrast innan sparning
- 🔴🟢🔵 **RGB-skjutreglage** för varje färgelement (0-255)
- 📐 **Rubrikstorlek** med live-förhandsvisning (10-32px)
- 💾 **Stor SPARA-knapp** alltid synlig
- 🔄 Automatisk backup till `desig.yaml.bak`
```markdown
# 🔒 Secure Data Manager

Ett säkert krypterings- och designsystem med tre självständiga program byggda i Rust.

## 🚀 Snabb överblick
Tre program i samma repository:
- `AI_databasen` — huvapp för kryptering, dekryptering och tabellvisning
- `aiagent_design` — GUI för att skapa och spara teman (desig.yaml)
- `bildagent` — enkel bildimport och formattering till `personer`-filen

Nedan listar jag funktioner per program och separerar säkerhetsfunktionerna i en egen sektion.

## � Funktioner

### AI_databasen (huvudprogram)
- Läser klartextdata från `personer` och sparar krypterad data i `personer2`
- Krypterar/dekrypterar med AES-256-GCM
- Lösenordsverifiering och hantering av flera ID (kategorier) i samma fil
- Sorterbar tabellvy med klickbara kolumnrubriker
- Visning av bilder inbäddade som Base64 i tabellen (skalade till miniatyrer)
- Dynamiska kolumnnamn och grid-alignment
- Tema-stöd via `desig.yaml`

### aiagent_design (designverktyg)
- Två arbetslägen: Prompt-läge (text-prompt) och Färgväljare (RGB-skjutreglage)
- Live-förhandsvisning och kontrastkontroll
- Spara tema till `desig.yaml` och automatiska backups

### bildagent (bildimport)
- GUI för att lägga till namn/ålder/yrke och importera en bild
- Konverterar bilder till Base64 och skriver rader i `personer` i formatet:
  `Namn Ålder Yrke [IMG:base64data]`
- Stödjer vanliga bildformat (PNG, JPEG, GIF, BMP, TIFF, WebP)

## 🔐 Säkerhetsfunktioner (separerade)

Här är alla säkerhetsrelaterade funktioner samlade:

- Krypteringsalgoritm: AES-256-GCM (AEAD)
- Key Derivation Function: Argon2id (standardparametrar: memory ≈128MB, iterations=4, parallelism=1)
- Per-post salt (16 bytes) och nonce (12 bytes) — varje post är unik
- Lösenordsverifiering: en verifierings-hash sparas i den krypterade posten
- Brute‑force-skydd: persistent räknare per ID, max 5 misslyckade försök → 15 minuters lockout
- Persistent lockout-data sparas i `personer2` så den överlever omstart
- Ingen klartext-lagring av lösenord i fil på disk
- Uppdatering utan att radera andra ID:n — flera ID:n kan samexistera i `personer2`

Format i `personer2` (per rad):
```
ID|base64(salt)|base64(nonce)|base64(ciphertext)|attempts|last_fail|lockout
```

Exempel (illustrativt):
```
personal|AbC...==|XyZ...==|encrypted...|0|0|0
```

Varningar / begränsningar:
- Lösenord kan vara närvarande i RAM under körning (undvik att lämna maskin obevakad)
- Argon2 kräver minne; på system med lite RAM kan parametrarna behöva justeras

## 📁 Filer (sammanfattning)

Körbara program (byggda från denna repo):
```
AI_databasen          # Huvudprogram
aiagent_design         # Designverktyg
bildagent              # Bildhantering
desig.yaml             # Tema-konfiguration
personer.bin               # Din data (Krypterad)

```

För utveckling:
```
AI_databasen.rs        # Huvudkoden (kan heta AI_databasen i binär)
aiagent_design.rs      # Källkod för aiagent_design
bildagent.rs           # Källkod för bildagent
desig.rs               # Delad modul för tema-laddning
Cargo.toml             # Byggkonfiguration
target/                # Kompilerade filer
```

### Automatiskt skapade/backup
```
desig.yaml.bak

```

## Bygga från källkod

```bash
cargo build --release
cp target/release/AI_databasen .           # eller AI_databasen beroende på binärnamn
cp target/release/aiagent_design .
cp target/release/bildagent .
chmod +x AI_databasen aiagent_design bildagent
```

## desig.yaml Format

```yaml
bg: [30,60,120]
text: [255,255,255]
heading_size: 18.0
row_even: [40,70,140]
row_odd: [25,50,110]
```

## Bildstöd

Rader i `personer` med `[IMG:...]` renderas som bilder i tabellen. Stödda format: PNG, JPEG, GIF, BMP, TIFF, WebP. Bilder skalas till miniatyrer (standard ~80x80) för visning.

## Kryptering & detaljer

- Algoritm: AES-256-GCM
- KDF: Argon2id (konfigurerbart i koden)
- Salt: 16 bytes per post
- Nonce: 12 bytes per post

I den krypterade datan sparas även en verifieringshash och metadata om försök/lockout.

## Felsökning (snabbt)

- Om programmet inte startar: se att binären är körbar (`chmod +x AI_databasen`)
- Se importer/loggar: `/home/matsu/databasen/import_debug.log` (skapas vid import)
- Om appen kraschar: kolla `/tmp/ai_databasen_panic.log` (om skrivet)

## Dependencies

- eframe / egui — GUI
- aes-gcm — AEAD-kryptering
- argon2 — key derivation
- base64 — encoding
- image — bildhantering (decoding/encoding)
- serde + serde_yaml — tema/parsing

---

Om du vill att jag lägger till en kort 'quickstart' längst upp eller genererar en svensk/engelsk dubbelversion, säg till så fixar jag det.
```

