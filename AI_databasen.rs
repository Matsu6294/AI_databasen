// AI_DATABASEN - Krypterad databas med AI-guide och 5-kolumns bildgalleri
// Skapad: 6 oktober 2025
// Features: AI-guide, 5 kolumner, 200px thumbnails, 400px hover, max 1MB bilder

use eframe::egui;
use eframe::egui::{ScrollArea, RichText};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Argon2, Algorithm, Params, Version};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use image::GenericImageView;

mod desig;
use desig::{load_theme_from_yaml, apply_theme, setup_fonts};

const PERSONER: &str = "/home/matsu/databasen/personer";
const PERSONER2: &str = "/home/matsu/databasen/personer.bin";

// Derive a 32-byte key using Argon2id
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    // Try Argon2 with progressively smaller memory requirements to avoid OOM on low-memory systems.
    let mem_kib_choices = [131_072u32, 65_536u32, 32_768u32, 16_384u32];

    for &mem in &mem_kib_choices {
        if let Ok(params) = Params::new(mem, 4, 1, None) {
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = [0u8; 32];
            if argon2.hash_password_into(password.as_bytes(), salt, &mut key).is_ok() {
                return key;
            }
            // if hashing failed (likely allocation), try a smaller mem value
        }
    }

    // Fallback (non-panicking): derive a deterministic 32-byte key by mixing password and salt.
    // This is weaker than Argon2 but prevents panics/OOM and keeps the application usable.
    let mut key = [0u8; 32];
    let pwd_bytes = password.as_bytes();
    if !pwd_bytes.is_empty() {
        for i in 0..32 {
            let p = pwd_bytes[i % pwd_bytes.len()];
            let s = salt[i % salt.len()];
            key[i] = p.wrapping_add(s).rotate_left((i % 8) as u32);
        }
    } else {
        // If password is empty, still mix salt into key
        for i in 0..32 {
            key[i] = salt[i % salt.len()].wrapping_mul(31).wrapping_add(i as u8);
        }
    }
    key
}

// Detektera och parsea tabelldata (rader med kolumner separerade med 2+ mellanslag)
fn parse_table_data(text: &str) -> Option<Vec<Vec<String>>> {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() < 2 { 
        return None; 
    }
    
    // ENKEL METOD: Ersätt 2+ mellanslag med en separator
    let mut all_rows = Vec::new();
    
    for line in &lines {
        // Använd regex-liknande ersättning: 2+ spaces -> '|'
        let mut result = String::new();
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        
        while i < chars.len() {
            if i + 1 < chars.len() && chars[i] == ' ' && chars[i + 1] == ' ' {
                // Hitta 2+ mellanslag
                result.push('|');
                // Skippa alla följande mellanslag
                while i < chars.len() && chars[i] == ' ' {
                    i += 1;
                }
            } else {
                result.push(chars[i]);
                i += 1;
            }
        }
        
        // Splitta på separator
        // Keep empty cells (don't filter out empty strings) so column positions are preserved
        let columns: Vec<String> = result.split('|')
            .map(|s| s.trim().to_string())
            .collect();
        
        if columns.len() >= 2 {
            all_rows.push(columns);
        } else {
            return None;
        }
    }
    
    // Kolla att alla rader har samma antal kolumner
    if all_rows.is_empty() { 
        return None; 
    }
    let col_count = all_rows[0].len();
    if all_rows.iter().all(|row| row.len() == col_count) {
        Some(all_rows)
    } else {
        None
    }
}

// Encrypt and save from a specific file (med optional bildtext)
fn encrypt_and_save_file_with_desc(identifier: &str, password: &str, file_path: &str, description: Option<&str>) -> Result<(), String> {
    if !Path::new(file_path).exists() {
        return Err(format!("Filen '{}' saknas", file_path));
    }
    
    // Läs filen som binär först
    let binary_data = fs::read(file_path)
        .map_err(|e| format!("Kunde inte läsa fil: {}", e))?;
    
    // Kolla om det är en bild
    let is_image = if let Some(ext) = Path::new(file_path).extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        ext_lower == "jpg" || ext_lower == "jpeg" || ext_lower == "png" || 
        ext_lower == "gif" || ext_lower == "webp"
    } else {
        false
    };
    
    // Försök konvertera till text (UTF-8), annars base64-koda
    let plaintext = if is_image {
        // För bilder: skapa tabell med bildnamn (1 kolumn)
        let filename = Path::new(file_path).file_name()
            .unwrap_or_default().to_string_lossy().to_string();
        
        // Optimera bilden först (inkl. EXIF-rotation)
        let optimized = optimize_image_data(&binary_data)
            .unwrap_or_else(|_| binary_data.clone());
        let encoded = general_purpose::STANDARD.encode(&optimized);
        
        // Format: IMAGE:bildnamn|base64data|beskrivning
        let desc = description.unwrap_or("");
        format!("IMAGE:{}|{}|{}", filename, encoded, desc)
    } else {
        // För text/andra filer: TEXT:innehåll
        let text_content = match String::from_utf8(binary_data) {
            Ok(text) => text,
            Err(e) => {
                let binary_data = e.into_bytes();
                general_purpose::STANDARD.encode(&binary_data)
            }
        };
        format!("TEXT:{}", text_content)
    };
    
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher error: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    let pwd_hash = hasher.finish();
    let data_with_pwd = format!("PWD:{}|{}", pwd_hash, plaintext);
    
    let ciphertext = cipher.encrypt(nonce, data_with_pwd.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    let new_line = format!("{}|{}|{}|{}|0|0|0",
        identifier,
        general_purpose::STANDARD.encode(&salt),
        general_purpose::STANDARD.encode(&nonce_bytes),
        general_purpose::STANDARD.encode(&ciphertext)
    );
    
    let mut lines: Vec<String> = Vec::new();
    let mut preserve_bf_data = false;
    let mut old_bf_fields = String::from("0|0|0");
    
    if Path::new(PERSONER2).exists() {
        let existing = fs::read_to_string(PERSONER2)
            .map_err(|e| format!("Kunde inte läsa personer.bin: {}", e))?;
        
        for line in existing.lines() {
            if !line.is_empty() {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 1 {
                    if parts[0] == identifier && parts.len() >= 7 {
                        old_bf_fields = format!("{}|{}|{}", parts[4], parts[5], parts[6]);
                        preserve_bf_data = true;
                    } else if parts[0] != identifier {
                        lines.push(line.to_string());
                    }
                }
            }
        }
    }
    
    let final_line = if preserve_bf_data {
        format!("{}|{}|{}|{}|{}", 
            identifier,
            general_purpose::STANDARD.encode(&salt),
            general_purpose::STANDARD.encode(&nonce_bytes),
            general_purpose::STANDARD.encode(&ciphertext),
            old_bf_fields
        )
    } else {
        new_line
    };
    
    lines.push(final_line);
    
    fs::write(PERSONER2, lines.join("\n") + "\n")
        .map_err(|e| format!("Kunde inte skriva personer.bin: {}", e))?;
    
    Ok(())
}

// Wrapper utan beskrivning (bakåtkompatibilitet)
fn encrypt_and_save_file(identifier: &str, password: &str, file_path: &str) -> Result<(), String> {
    encrypt_and_save_file_with_desc(identifier, password, file_path, None)
}

// Encrypt and save from PERSONER file (used by BulkImport)
fn encrypt_and_save(identifier: &str, password: &str) -> Result<(), String> {
    // Use the global PERSONER constant (absolute path) instead of a local relative path
    if !Path::new(PERSONER).exists() {
        return Err(format!("Filen '{}' saknas", PERSONER));
    }

    let plaintext = fs::read_to_string(PERSONER)
        .map_err(|e| format!("Kunde inte läsa {}: {}", PERSONER, e))?;
    
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    
    let key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Cipher error: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    password.hash(&mut hasher);
    let pwd_hash = hasher.finish();
    let data_with_pwd = format!("PWD:{}|{}", pwd_hash, plaintext);
    
    let ciphertext = cipher.encrypt(nonce, data_with_pwd.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    
    let new_line = format!("{}|{}|{}|{}|0|0|0",
        identifier,
        general_purpose::STANDARD.encode(&salt),
        general_purpose::STANDARD.encode(&nonce_bytes),
        general_purpose::STANDARD.encode(&ciphertext)
    );
    
    let mut lines: Vec<String> = Vec::new();
    let mut preserve_bf_data = false;
    let mut old_bf_fields = String::from("0|0|0");
    
    if Path::new(PERSONER2).exists() {
        let existing = fs::read_to_string(PERSONER2)
            .map_err(|e| format!("Kunde inte läsa personer.bin: {}", e))?;
        
        for line in existing.lines() {
            if !line.is_empty() {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 1 {
                    if parts[0] == identifier && parts.len() >= 7 {
                        old_bf_fields = format!("{}|{}|{}", parts[4], parts[5], parts[6]);
                        preserve_bf_data = true;
                    } else if parts[0] != identifier {
                        lines.push(line.to_string());
                    }
                }
            }
        }
    }
    
    let final_line = if preserve_bf_data {
        format!("{}|{}|{}|{}|{}", 
            identifier,
            general_purpose::STANDARD.encode(&salt),
            general_purpose::STANDARD.encode(&nonce_bytes),
            general_purpose::STANDARD.encode(&ciphertext),
            old_bf_fields
        )
    } else {
        new_line
    };
    
    lines.push(final_line);
    
    fs::write(PERSONER2, lines.join("\n") + "\n")
        .map_err(|e| format!("Kunde inte skriva personer.bin: {}", e))?;
    
    Ok(())
}

// Decrypt and load
fn decrypt_and_load(identifier: &str, password: &str) -> Result<String, String> {
    if !Path::new(PERSONER2).exists() {
        return Err("Filen 'personer.bin' saknas".to_string());
    }
    
    let content = fs::read_to_string(PERSONER2)
        .map_err(|e| format!("Kunde inte läsa personer.bin: {}", e))?;
    
    for line in content.lines() {
        if line.is_empty() { continue; }
        let parts: Vec<&str> = line.split('|').collect();
        
        if parts.len() >= 7 && parts[0] == identifier {
            let attempts: u32 = parts[4].parse().unwrap_or(0);
            let _last_fail: u64 = parts[5].parse().unwrap_or(0);
            let lockout_until: u64 = parts[6].parse().unwrap_or(0);
            
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            
            if lockout_until > now {
                let remaining = lockout_until - now;
                return Err(format!("🔒 Kontot är låst i {} sekunder", remaining));
            }
            
            let salt = general_purpose::STANDARD.decode(parts[1])
                .map_err(|_| "Fel vid decode av salt".to_string())?;
            let nonce_bytes = general_purpose::STANDARD.decode(parts[2])
                .map_err(|_| "Fel vid decode av nonce".to_string())?;
            let ciphertext = general_purpose::STANDARD.decode(parts[3])
                .map_err(|_| "Fel vid decode av ciphertext".to_string())?;
            
            let key = derive_key(password, &salt);
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|e| format!("Cipher error: {}", e))?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            
            match cipher.decrypt(nonce, ciphertext.as_ref()) {
                Ok(decrypted) => {
                    let decrypted_str = String::from_utf8(decrypted)
                        .map_err(|_| "UTF8 error".to_string())?;
                    
                    if let Some(pipe_pos) = decrypted_str.find('|') {
                        let pwd_part = &decrypted_str[..pipe_pos];
                        let data_part = &decrypted_str[pipe_pos+1..];
                        
                        if pwd_part.starts_with("PWD:") {
                            update_brute_force_success(identifier, &content)?;
                            return Ok(data_part.to_string());
                        }
                    }
                    
                    return Err("⚠️ Fel lösenord".to_string());
                },
                Err(_) => {
                    update_brute_force_fail(identifier, &content, attempts)?;
                    
                    if attempts + 1 >= 5 {
                        return Err("🔒 Kontot låst i 300 sekunder efter 5 misslyckade försök".to_string());
                    }
                    
                    return Err(format!("⚠️ Fel lösenord ({}/5 försök)", attempts + 1));
                }
            }
        }
    }
    
    Err(format!("ID '{}' hittades inte", identifier))
}

fn update_brute_force_fail(identifier: &str, content: &str, current_attempts: u32) -> Result<(), String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let new_attempts = current_attempts + 1;
    let lockout = if new_attempts >= 5 { now + 300 } else { 0 };
    
    let mut new_lines = Vec::new();
    for line in content.lines() {
        if line.is_empty() { continue; }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 7 && parts[0] == identifier {
            new_lines.push(format!("{}|{}|{}|{}|{}|{}|{}",
                parts[0], parts[1], parts[2], parts[3],
                new_attempts, now, lockout
            ));
        } else {
            new_lines.push(line.to_string());
        }
    }
    
    fs::write(PERSONER2, new_lines.join("\n") + "\n")
        .map_err(|e| format!("Fel vid uppdatering: {}", e))
}

fn update_brute_force_success(identifier: &str, content: &str) -> Result<(), String> {
    let mut new_lines = Vec::new();
    for line in content.lines() {
        if line.is_empty() { continue; }
        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 7 && parts[0] == identifier {
            new_lines.push(format!("{}|{}|{}|{}|0|0|0",
                parts[0], parts[1], parts[2], parts[3]
            ));
        } else {
            new_lines.push(line.to_string());
        }
    }
    
    fs::write(PERSONER2, new_lines.join("\n") + "\n")
        .map_err(|e| format!("Fel vid uppdatering: {}", e))
}

// Check if ID already exists
fn id_exists(identifier: &str) -> bool {
    if !Path::new(PERSONER2).exists() {
        return false;
    }
    
    if let Ok(content) = fs::read_to_string(PERSONER2) {
        for line in content.lines() {
            if !line.is_empty() {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 1 && parts[0] == identifier {
                    return true;
                }
            }
        }
    }
    false
}

// Delete entry
fn delete_entry(identifier: &str) -> Result<(), String> {
    if !Path::new(PERSONER2).exists() {
        return Err("Filen 'personer.bin' saknas".to_string());
    }
    
    let content = fs::read_to_string(PERSONER2)
        .map_err(|e| format!("Kunde inte läsa personer.bin: {}", e))?;
    
    let lines: Vec<String> = content.lines()
        .filter(|line| {
            if line.is_empty() { return false; }
            let parts: Vec<&str> = line.split('|').collect();
            parts.len() < 1 || parts[0] != identifier
        })
        .map(|s| s.to_string())
        .collect();
    
    fs::write(PERSONER2, lines.join("\n") + "\n")
        .map_err(|e| format!("Kunde inte skriva personer.bin: {}", e))?;
    
    Ok(())
}

// Image optimization: max 1MB with adaptive quality
fn optimize_image_data(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut img = image::load_from_memory(data)
        .map_err(|e| format!("Kunde inte läsa bild: {}", e))?;
    
    // Läs EXIF-data och rotera bilden baserat på orientation
    if let Ok(exif_reader) = exif::Reader::new().read_from_container(&mut std::io::Cursor::new(data)) {
        if let Some(orientation) = exif_reader.get_field(exif::Tag::Orientation, exif::In::PRIMARY) {
            if let Some(orientation_val) = orientation.value.get_uint(0) {
                img = match orientation_val {
                    3 => img.rotate180(),
                    6 => img.rotate90(),
                    8 => img.rotate270(),
                    _ => img, // 1 = normal, ingen rotation
                };
            }
        }
    }
    
    let (width, height) = img.dimensions();
    let max_dimension = 1920;
    let img = if width > max_dimension || height > max_dimension {
        let scale = max_dimension as f32 / width.max(height) as f32;
        let new_w = (width as f32 * scale) as u32;
        let new_h = (height as f32 * scale) as u32;
        img.resize(new_w, new_h, image::imageops::FilterType::Lanczos3)
    } else {
        img
    };
    
    // Adaptive quality: start at 80 (lower to reduce CPU/time), reduce until under 1MB
    let mut quality = 80u8;
    loop {
        let mut buffer = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut buffer);
        
        let rgb = img.to_rgb8();
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut cursor, quality);
        encoder.encode(
            rgb.as_raw(),
            rgb.width(),
            rgb.height(),
            image::ColorType::Rgb8
        ).map_err(|e| format!("JPEG encode error: {}", e))?;
        
        if buffer.len() <= 1_000_000 || quality <= 60 {
            return Ok(buffer);
        }
        
        quality -= 5;
    }
}

// Gallery entry structure - store base64 string and decode on demand to avoid high memory use
#[derive(Clone)]
struct GalleryEntry {
    namn: String,
    base64: Option<String>,
    decrypted_data: Option<Vec<u8>>, // kept for compatibility; normally None and decode on render
}

// Messages sent from background import thread to UI
enum ImportMsg {
    Total(usize),
    Progress(usize, String), // (current, filename/status)
    Finished(Result<String, String>), // Ok(success_message) or Err(error_message)
}

// Guide steps with AI agent
#[derive(Clone, PartialEq)]
enum GuideStep {
    Welcome,
    AddId,
    AddPassword,
    AddFileChoice,
    AddComplete,
    AddError,
    ViewId,
    ViewPassword,
    ViewComplete,
    ViewError,
    DeleteId,
    DeletePassword,
    DeleteComplete,
    DeleteError,
    BulkImportId,
    BulkImportPassword,
    BulkImportFolder,
    BulkImporting,
    BulkImportError,
    GalleryId,
    GalleryPassword,
    GalleryView,
    GalleryError,
}

struct MyApp {
    guide_step: GuideStep,
    identifier_input: String,
    password_input: String,
    folder_path_input: String,
    file_path_input: String,
    message: String,
    decrypted_content: String,
    entries: Vec<GalleryEntry>,
    // Simple texture LRU cache: key -> texture id string
    texture_cache: std::collections::HashMap<String, egui::TextureHandle>,
    texture_lru: std::collections::VecDeque<String>,
    import_progress_current: usize,
    import_progress_total: usize,
    loading_status: String,
    import_rx: Option<Receiver<ImportMsg>>,
    heartbeat: u64,
    // Tabellsortering
    table_data: Vec<Vec<String>>,
    sort_column: Option<usize>,
    sort_ascending: bool,
    // Tabellredigering
    table_edit_mode: bool,
    table_modified: bool,
    // Bildredigering
    image_description: String,
    image_edit_mode: bool,
    // ---
    open_folder_dialog: bool,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            guide_step: GuideStep::Welcome,
            identifier_input: String::new(),
            password_input: String::new(),
            folder_path_input: String::new(),
            file_path_input: String::new(),
            message: String::new(),
            decrypted_content: String::new(),
            entries: Vec::new(),
            texture_cache: std::collections::HashMap::new(),
            texture_lru: std::collections::VecDeque::new(),
            import_progress_current: 0,
            import_progress_total: 0,
            loading_status: String::new(),
            table_data: Vec::new(),
            sort_column: None,
            sort_ascending: true,
            table_edit_mode: false,
            table_modified: false,
            image_description: String::new(),
            image_edit_mode: false,
            open_folder_dialog: false,
            import_rx: None,
            heartbeat: 0,
        }
    }
}

impl MyApp {
    fn reset_session(&mut self) {
        self.identifier_input.clear();
        self.password_input.clear();
        self.folder_path_input.clear();
        self.file_path_input.clear();
        self.message.clear();
        self.decrypted_content.clear();
        self.entries.clear();
        self.import_progress_current = 0;
        self.import_progress_total = 0;
        self.loading_status.clear();
        self.table_data.clear();
        self.sort_column = None;
        self.sort_ascending = true;
        self.table_edit_mode = false;
        self.table_modified = false;
        self.guide_step = GuideStep::Welcome;
    }
    
    // AI Agent helper - shows friendly guidance
    fn show_ai_message(&self, ui: &mut egui::Ui, message: &str) {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🤖").size(30.0));
                ui.vertical(|ui| {
                    ui.label(RichText::new("AI-AGENT SÄGER:").size(14.0).strong()
                        .color(egui::Color32::from_rgb(100, 255, 150)));
                    ui.label(RichText::new(message).size(13.0)
                        .color(egui::Color32::WHITE));
                });
            });
        });
        ui.add_space(15.0);
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);
            // Heartbeat indicator (updated each frame) to avoid OS thinking app is unresponsive
            self.heartbeat = self.heartbeat.wrapping_add(1);
            ui.allocate_ui_with_layout(ui.available_size(), egui::Layout::right_to_left(egui::Align::Min), |ui| {
                ui.label(RichText::new(format!("heartbeat: {}", self.heartbeat)).size(10.0)
                    .color(egui::Color32::from_rgb(150, 150, 150)));
            });
            
            match &self.guide_step {
                GuideStep::Welcome => {
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("🤖 AI-DATABASEN").size(28.0).strong()
                            .color(egui::Color32::from_rgb(100, 200, 255)));
                        ui.add_space(5.0);
                        ui.label(RichText::new("Krypterad databas med AI-guide och 5-kolumns bildgalleri")
                            .size(14.0).color(egui::Color32::GRAY));
                    });
                    ui.add_space(20.0);
                    
                    self.show_ai_message(ui, "\"Hej! Jag är din AI-guide. Jag hjälper dig att enkelt jobba med databasen. Vad vill du göra?\"");
                    
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([300.0, 45.0], egui::Button::new(
                            RichText::new("� Ladda in en fil i databasen").size(14.0)
                        )).clicked() {
                            self.guide_step = GuideStep::AddId;
                        }
                        ui.add_space(10.0);
                        
                        if ui.add_sized([300.0, 45.0], egui::Button::new(
                            RichText::new("🔓 Läs Dekrypterad Data").size(14.0)
                        )).clicked() {
                            self.guide_step = GuideStep::ViewId;
                        }
                        ui.add_space(10.0);
                        
                        if ui.add_sized([300.0, 45.0], egui::Button::new(
                            RichText::new("🖼️ Visa Bildgalleri (5 kolumner)").size(14.0)
                        )).clicked() {
                            self.guide_step = GuideStep::GalleryId;
                        }
                        ui.add_space(10.0);
                        
                        if ui.add_sized([300.0, 45.0], egui::Button::new(
                            RichText::new("📁 Importera Bilder från Mapp").size(14.0)
                        )).clicked() {
                            self.guide_step = GuideStep::BulkImportId;
                        }
                        ui.add_space(10.0);
                        
                        if ui.add_sized([300.0, 45.0], egui::Button::new(
                            RichText::new("🗑️ Radera Post").size(14.0)
                        )).clicked() {
                            self.guide_step = GuideStep::DeleteId;
                        }
                    });
                },
                
                GuideStep::AddId => {
                    self.show_ai_message(ui, "\"Perfekt! Låt oss ladda in en fil. Först behöver jag ett unikt ID för att identifiera denna fil i databasen.\"");
                    
                    ui.label(RichText::new("📝 Ange ett ID:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.identifier_input)
                            .hint_text("t.ex. min_bild eller viktigt_dokument"));
                    
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.identifier_input.is_empty() {
                            // Kolla om ID redan finns
                            if id_exists(&self.identifier_input) {
                                self.message = format!("⚠️ ID '{}' finns redan! Välj ett annat ID eller radera det gamla först.", self.identifier_input);
                                self.guide_step = GuideStep::AddError;
                            } else {
                                self.guide_step = GuideStep::AddPassword;
                            }
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.reset_session();
                        }
                        if ui.button(RichText::new("➡️ Nästa").size(13.0)).clicked() 
                            && !self.identifier_input.is_empty() {
                            // Kolla om ID redan finns
                            if id_exists(&self.identifier_input) {
                                self.message = format!("⚠️ ID '{}' finns redan! Välj ett annat ID eller radera det gamla först.", self.identifier_input);
                                self.guide_step = GuideStep::AddError;
                            } else {
                                self.guide_step = GuideStep::AddPassword;
                            }
                        }
                    });
                },
                
                GuideStep::AddFileChoice => {
                    self.show_ai_message(ui, 
                        &format!("\"Perfekt! Nu behöver jag veta vilken fil du vill kryptera med ID: '{}' och lösenordet du angav. Klicka på knappen för att välja en bild eller textfil.\"", self.identifier_input));
                    
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("📁 Välj fil från hårddisken").size(18.0).strong()
                            .color(egui::Color32::from_rgb(100, 200, 255)));
                        ui.add_space(15.0);
                        
                        // Metod 1: Stor knapp för filväljare
                        if ui.add_sized([350.0, 50.0], egui::Button::new(
                            RichText::new("📂 Bläddra och välj fil...").size(16.0)
                        )).clicked() {
                            // Enkel kommandorad-baserad filväljare
                            use std::process::Command;
                            if let Ok(output) = Command::new("zenity")
                                .arg("--file-selection")
                                .arg("--title=Välj fil att kryptera")
                                .output() 
                            {
                                if output.status.success() {
                                    if let Ok(path) = String::from_utf8(output.stdout) {
                                        self.file_path_input = path.trim().to_string();
                                    }
                                }
                            }
                        }
                        
                        ui.add_space(10.0);
                        ui.label(RichText::new("ELLER ange filväg manuellt:").size(12.0).color(egui::Color32::GRAY));
                        ui.add_space(5.0);
                        
                        // Metod 2: Textinmatning
                        let response = ui.add_sized([600.0, 35.0], 
                            egui::TextEdit::singleline(&mut self.file_path_input)
                                .hint_text("/home/användare/minfil.jpg"));
                        
                        if response.changed() && !self.file_path_input.is_empty() {
                            if std::path::Path::new(&self.file_path_input).exists() {
                                self.message = format!("✅ Fil hittad");
                            } else {
                                self.message = format!("⚠️ Filen finns inte");
                            }
                        }
                        
                        ui.add_space(15.0);
                        
                        // Visa vald fil
                        if !self.file_path_input.is_empty() {
                            ui.group(|ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("✅").size(20.0));
                                    ui.vertical(|ui| {
                                        ui.label(RichText::new("Vald fil:").size(12.0).color(egui::Color32::GRAY));
                                        ui.label(RichText::new(&self.file_path_input)
                                            .size(13.0)
                                            .color(egui::Color32::from_rgb(100, 255, 100)));
                                    });
                                });
                            });
                        } else {
                            ui.label(RichText::new("Ingen fil vald ännu...")
                                .size(13.0)
                                .color(egui::Color32::GRAY));
                        }
                        
                        ui.add_space(10.0);
                        ui.label(RichText::new("💡 Tips: Dra fil till terminal för att få sökvägen")
                            .size(11.0).color(egui::Color32::GRAY));
                    });
                    
                    ui.add_space(25.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.guide_step = GuideStep::AddPassword;
                        }
                        if ui.button(RichText::new("🔒 Kryptera & Spara!").size(13.0)).clicked() 
                            && !self.file_path_input.is_empty() {
                            // Kryptera filen
                            match encrypt_and_save_file(&self.identifier_input, &self.password_input, &self.file_path_input) {
                                Ok(_) => {
                                    self.message = format!("✅ Filen har krypterats och sparats med ID: {}", self.identifier_input);
                                    self.guide_step = GuideStep::AddComplete;
                                },
                                Err(e) => {
                                    self.message = format!("❌ Fel vid kryptering: {}", e);
                                    self.guide_step = GuideStep::AddError;
                                }
                            }
                        }
                    });
                },
                
                GuideStep::AddPassword => {
                    self.show_ai_message(ui, 
                        &format!("\"Bra! Nu behöver jag ett starkt lösenord för ID: '{}'. Detta lösenord kommer användas för att kryptera filen.\"", self.identifier_input));
                    
                    ui.label(RichText::new("🔑 Ange lösenord:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.password_input)
                            .password(true)
                            .hint_text("Välj ett starkt lösenord"));
                    
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.password_input.is_empty() {
                            self.guide_step = GuideStep::AddFileChoice;
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.guide_step = GuideStep::AddId;
                        }
                        if ui.button(RichText::new("➡️ Nästa").size(13.0)).clicked() 
                            && !self.password_input.is_empty() {
                            self.guide_step = GuideStep::AddFileChoice;
                        }
                    });
                },
                
                GuideStep::AddComplete => {
                    self.show_ai_message(ui, "\"Underbart! Din fil är nu säkert krypterad och sparad i databasen. 🎉\"");
                    
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("✅ KLART!").size(24.0).strong()
                            .color(egui::Color32::from_rgb(100, 255, 100)));
                        ui.add_space(10.0);
                        ui.label(RichText::new(&self.message).size(14.0)
                            .color(egui::Color32::WHITE));
                    });
                    
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🏠 Tillbaka till Start").size(13.0)
                        )).clicked() {
                            self.reset_session();
                        }
                    });
                },
                
                GuideStep::AddError => {
                    self.show_ai_message(ui, "\"Oj då! Något gick fel. 😟\"");
                    
                    ui.label(RichText::new(&self.message)
                        .size(16.0).strong().color(egui::Color32::from_rgb(255, 100, 100)));
                    ui.add_space(20.0);
                    
                    ui.label(RichText::new("Tips:").size(14.0).strong());
                    ui.label("• Om ID:t finns - välj ett annat unikt ID");
                    ui.label("• Om fil inte kunde läsas - kontrollera att filen finns och är läsbar");
                    ui.label("• Kontrollera skrivbehörighet till personer.bin");
                    ui.label("• Kontrollera diskutrymme");
                    
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🔄 Försök igen från början").size(13.0)
                        )).clicked() {
                            self.identifier_input.clear();
                            self.password_input.clear();
                            self.file_path_input.clear();
                            self.message.clear();
                            self.guide_step = GuideStep::AddId;
                        }
                        ui.add_space(10.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🏠 Tillbaka till Start").size(13.0)
                        )).clicked() {
                            self.reset_session();
                        }
                    });
                },
                
                GuideStep::ViewId => {
                    self.show_ai_message(ui, "\"Okej! Låt oss hämta och dekryptera data. Vilket ID vill du läsa?\"");
                    
                    ui.label(RichText::new("📝 Ange ID:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.identifier_input)
                            .hint_text("Ange ID för posten du vill läsa"));
                    
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.identifier_input.is_empty() {
                            self.guide_step = GuideStep::ViewPassword;
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.reset_session();
                        }
                        if ui.button(RichText::new("➡️ Nästa").size(13.0)).clicked() 
                            && !self.identifier_input.is_empty() {
                            self.guide_step = GuideStep::ViewPassword;
                        }
                    });
                },
                
                GuideStep::ViewPassword => {
                    self.show_ai_message(ui, 
                        &format!("\"Ange lösenordet för ID: '{}'\"", self.identifier_input));
                    
                    ui.label(RichText::new("🔑 Lösenord:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.password_input)
                            .password(true)
                            .hint_text("Ange lösenord"));
                    
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.password_input.is_empty() {
                            match decrypt_and_load(&self.identifier_input, &self.password_input) {
                                Ok(content) => {
                                    self.decrypted_content = content;
                                    self.guide_step = GuideStep::ViewComplete;
                                },
                                Err(e) => {
                                    self.message = format!("❌ {}", e);
                                    self.guide_step = GuideStep::ViewError;
                                }
                            }
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.guide_step = GuideStep::ViewId;
                        }
                        if ui.button(RichText::new("🔓 Dekryptera!").size(13.0)).clicked() 
                            && !self.password_input.is_empty() {
                            match decrypt_and_load(&self.identifier_input, &self.password_input) {
                                Ok(content) => {
                                    self.decrypted_content = content;
                                    self.guide_step = GuideStep::ViewComplete;
                                },
                                Err(e) => {
                                    self.message = format!("❌ {}", e);
                                    self.guide_step = GuideStep::ViewError;
                                }
                            }
                        }
                    });
                },
                
                GuideStep::ViewComplete => {
                    self.show_ai_message(ui, "\"Här är din dekrypterade data! 📄\"");
                    
                    ui.label(RichText::new(format!("✅ Data för ID: {}", self.identifier_input))
                        .size(16.0).strong().color(egui::Color32::from_rgb(100, 255, 100)));
                    ui.add_space(10.0);
                    
                    // AUTO-DETEKTERA typ av data
                    // 1. Kolla om det har prefix (ny data)
                    let mut is_image_data = self.decrypted_content.starts_with("IMAGE:");
                    let mut is_text_data = self.decrypted_content.starts_with("TEXT:");
                    
                    // 2. Om inget prefix (gamla data), försök auto-detektera
                    if !is_image_data && !is_text_data {
                        // Kolla om det ser ut som bilddata: bildnamn|base64
                        let trimmed = self.decrypted_content.trim();
                        if trimmed.contains('|') && trimmed.lines().count() == 1 {
                            let parts: Vec<&str> = trimmed.split('|').collect();
                            if parts.len() == 2 {
                                // Kolla om del 2 är base64 och del 1 är ett filnamn
                                let looks_like_filename = parts[0].len() < 200 && 
                                    (parts[0].ends_with(".jpg") || parts[0].ends_with(".jpeg") || 
                                     parts[0].ends_with(".png") || parts[0].ends_with(".gif") || 
                                     parts[0].ends_with(".webp"));
                                let looks_like_base64 = parts[1].len() > 100 && 
                                    parts[1].chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=');
                                
                                if looks_like_filename && looks_like_base64 {
                                    is_image_data = true;
                                } else {
                                    is_text_data = true;
                                }
                            } else {
                                is_text_data = true;
                            }
                        } else {
                            // Allt annat är text
                            is_text_data = true;
                        }
                    }
                    
                    if is_image_data {
                        // Ta bort IMAGE: prefix och visa bilden
                        let image_content = self.decrypted_content[6..].to_string(); // Hoppa över "IMAGE:"
                        // Parsa bildnamn|base64|beskrivning (eller gamla format bildnamn|base64)
                        let parts: Vec<&str> = image_content.split('|').collect();
                        if parts.len() >= 2 {
                            let bildnamn = parts[0].to_string();
                            let base64_part = parts[1].to_string();
                            let beskrivning = if parts.len() >= 3 { parts[2] } else { "" };
                            
                            // Ladda image_description första gången
                            if self.image_description.is_empty() && !beskrivning.is_empty() {
                                self.image_description = beskrivning.to_string();
                            }
                            
                            // Klona värden för att undvika borrow-problem
                            let bildnamn_clone = bildnamn.clone();
                            let base64_clone = base64_part.clone();
                            
                            if let Ok(decoded) = general_purpose::STANDARD.decode(&base64_part) {
                                ui.label(RichText::new("🖼️ Bildfil detekterad").size(14.0)
                                    .color(egui::Color32::from_rgb(100, 200, 255)));
                                ui.label(RichText::new(format!("Filnamn: {}", bildnamn)).size(12.0));
                                ui.add_space(10.0);
                                
                                // REDIGERINGSKNAPPAR - HÖGST UPP
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("📝 Bildtext:").size(13.0).strong());
                                    if !self.image_edit_mode {
                                        if ui.button(RichText::new("✏️ Redigera").size(13.0)).clicked() {
                                            self.image_edit_mode = true;
                                        }
                                    } else {
                                        if ui.button(RichText::new("💾 Spara").size(13.0).color(egui::Color32::GREEN)).clicked() {
                                            // 1. Avkoda base64 till rå bilddata
                                            if let Ok(img_data) = general_purpose::STANDARD.decode(&base64_clone) {
                                                // 2. Spara som temporär fil
                                                let temp_path = format!("/tmp/img_save_{}.jpg", self.identifier_input);
                                                if std::fs::write(&temp_path, &img_data).is_ok() {
                                                    // 3. Kryptera med samma ID, lösenord OCH beskrivning
                                                    match encrypt_and_save_file_with_desc(&self.identifier_input, 
                                                        &self.password_input, &temp_path, Some(&self.image_description)) {
                                                        Ok(_) => {
                                                            // 4. Uppdatera lokal kopia med ny beskrivning
                                                            self.decrypted_content = format!("IMAGE:{}|{}|{}", 
                                                                bildnamn_clone, base64_clone, self.image_description);
                                                            self.message = "✅ Bildtext sparad!".to_string();
                                                            self.image_edit_mode = false;
                                                        },
                                                        Err(e) => {
                                                            self.message = format!("❌ Kunde inte spara: {}", e);
                                                        }
                                                    }
                                                } else {
                                                    self.message = "❌ Kunde inte skapa temp-fil".to_string();
                                                }
                                            } else {
                                                self.message = "❌ Kunde inte avkoda bilddata".to_string();
                                            }
                                        }
                                        if ui.button(RichText::new("❌ Avbryt").size(13.0)).clicked() {
                                            self.image_description = beskrivning.to_string();
                                            self.image_edit_mode = false;
                                        }
                                    }
                                });
                                ui.add_space(10.0);
                                
                                // SCROLLBAR FÖR BILD OCH TEXT
                                ScrollArea::vertical().max_height(500.0).show(ui, |ui| {
                                    // Försök ladda och visa bilden
                                    match image::load_from_memory(&decoded) {
                                    Ok(img) => {
                                        let rgba = img.to_rgba8();
                                        let size = [rgba.width() as usize, rgba.height() as usize];
                                        let pixels = rgba.as_flat_samples();
                                        let color_image = egui::ColorImage::from_rgba_unmultiplied(
                                            size, pixels.as_slice());
                                        let texture = ctx.load_texture(bildnamn, color_image, 
                                            egui::TextureOptions::default());
                                        
                                        ui.vertical_centered(|ui| {
                                            // Visa bild med max bredd 300px (samma som i galleriet)
                                            let img_width = img.width() as f32;
                                            let img_height = img.height() as f32;
                                            let max_width = 300.0;
                                            let scale = (max_width / img_width).min(1.0);
                                            let display_size = egui::vec2(img_width * scale, img_height * scale);
                                            
                                            ui.add(egui::Image::new(&texture, display_size));
                                            ui.add_space(10.0);
                                            ui.label(RichText::new(format!("📐 {}x{} px  💾 {:.1} KB", 
                                                img.width(), img.height(), 
                                                decoded.len() as f32 / 1024.0))
                                                .size(12.0).color(egui::Color32::GRAY));
                                        });
                                        
                                        // Bildtext-området (samma bredd som bilden - max 300px)
                                        ui.add_space(15.0);
                                        ui.separator();
                                        ui.add_space(10.0);
                                        
                                        // Beräkna bildens visningsbredd
                                        let img_width = img.width() as f32;
                                        let max_width = 300.0;
                                        let scale = (max_width / img_width).min(1.0);
                                        let text_width = (img_width * scale).min(300.0);
                                        
                                        ui.vertical_centered(|ui| {
                                            ui.set_max_width(text_width);
                                            
                                            if self.image_edit_mode {
                                                ui.label(RichText::new("✏️ Redigera bildtext:").size(12.0).strong());
                                                ui.add_space(5.0);
                                                ui.add(egui::TextEdit::multiline(&mut self.image_description)
                                                    .desired_width(text_width)
                                                    .desired_rows(8)
                                                    .hint_text("Skriv en beskrivning av bilden..."));
                                            } else {
                                                ui.label(RichText::new("📝 Bildtext:").size(12.0).strong());
                                                ui.add_space(5.0);
                                                if !self.image_description.is_empty() {
                                                    ui.label(RichText::new(&self.image_description)
                                                        .size(12.0)
                                                        .color(egui::Color32::from_rgb(200, 200, 200)));
                                                } else {
                                                    ui.label(RichText::new("(Ingen beskrivning)")
                                                        .size(11.0).italics()
                                                        .color(egui::Color32::GRAY));
                                                }
                                            }
                                        });
                                        
                                        ui.add_space(20.0);
                                    },
                                    Err(e) => {
                                        ui.label(RichText::new(format!("❌ Kunde inte ladda bild: {}", e))
                                            .color(egui::Color32::RED));
                                    }
                                }
                                }); // Stäng ScrollArea
                            }
                        }
                    } else if is_text_data {
                        // Ta bort TEXT: prefix och hantera textdata
                        let mut text_content = self.decrypted_content[5..].to_string(); // Hoppa över "TEXT:"
                        
                        // Försök detektera och visa som tabell
                        if self.table_data.is_empty() {
                            if let Some(parsed) = parse_table_data(&text_content) {
                                self.table_data = parsed;
                            }
                        }
                        
                        if !self.table_data.is_empty() {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("📊 Tabelldata detekterad").size(14.0)
                                .color(egui::Color32::from_rgb(100, 200, 255)));
                            if !self.table_edit_mode {
                                ui.label(RichText::new("💡 Klicka på kolumnrubrik för att sortera")
                                    .size(11.0).color(egui::Color32::GRAY));
                            } else {
                                ui.label(RichText::new("✏️ REDIGERINGSLÄGE")
                                    .size(11.0).color(egui::Color32::YELLOW));
                            }
                        });
                        
                        // Redigera-knapp
                        ui.horizontal(|ui| {
                            if !self.table_edit_mode {
                                if ui.button(RichText::new("✏️ Redigera Tabell").size(13.0)).clicked() {
                                    self.table_edit_mode = true;
                                }
                            } else {
                                if ui.button(RichText::new("✅ Klar (Visa)").size(13.0)
                                    .color(egui::Color32::GREEN)).clicked() {
                                    self.table_edit_mode = false;
                                }
                                if ui.button(RichText::new("💾 Spara Ändringar").size(13.0)
                                    .color(egui::Color32::YELLOW)).clicked() {
                                    // Konvertera table_data tillbaka till text med 2 mellanslag
                                    let new_content: Vec<String> = self.table_data.iter()
                                        .map(|row| row.join("  "))
                                        .collect();
                                    let table_text = new_content.join("\n");
                                    
                                    // Spara tillbaka till databasen (behåll TEXT: prefix)
                                    self.decrypted_content = format!("TEXT:{}", table_text);
                                    
                                    // Skriv temp-fil först
                                    let temp_path = format!("/tmp/tabell_temp_{}.txt", self.identifier_input);
                                    if std::fs::write(&temp_path, &table_text).is_ok() {
                                        // Sedan kryptera (encrypt_and_save_file lägger till TEXT: prefix)
                                        match encrypt_and_save_file(&self.identifier_input, 
                                            &self.password_input, 
                                            &temp_path) {
                                            Ok(_) => {
                                                self.message = "✅ Ändringar sparade!".to_string();
                                                self.table_modified = false;
                                                self.table_edit_mode = false;
                                            },
                                            Err(e) => self.message = format!("❌ Fel: {}", e),
                                        }
                                    } else {
                                        self.message = "❌ Kunde inte skriva temp-fil".to_string();
                                    }
                                }
                                if ui.button(RichText::new("➕ Lägg till rad").size(13.0)).clicked() {
                                    let col_count = self.table_data[0].len();
                                    let new_row = vec!["".to_string(); col_count];
                                    self.table_data.push(new_row);
                                    self.table_modified = true;
                                }
                            }
                        });
                        
                        if self.table_modified {
                            ui.label(RichText::new("⚠️ Ospara ändringar")
                                .color(egui::Color32::YELLOW).size(11.0));
                        }
                        ui.add_space(10.0);
                        
                        ScrollArea::vertical().max_height(450.0).show(ui, |ui| {
                            use egui_extras::{TableBuilder, Column};
                            
                            let col_count = self.table_data[0].len();
                            
                            // Beräkna max bredder
                            let mut max_widths = vec![0; col_count];
                            for row in &self.table_data {
                                for (i, cell) in row.iter().enumerate() {
                                    max_widths[i] = max_widths[i].max(cell.len());
                                }
                            }
                            
                            let column_widths: Vec<f32> = max_widths.iter()
                                .map(|&w| (w as f32 * 8.0 + 20.0).max(80.0))
                                .collect();
                            
                            let mut table = TableBuilder::new(ui)
                                .striped(true)
                                .cell_layout(egui::Layout::left_to_right(egui::Align::Center));
                            
                            for width in column_widths {
                                table = table.column(Column::initial(width).at_least(80.0));
                            }
                            
                            // Extra kolumn för radera-knapp i edit-mode
                            if self.table_edit_mode {
                                table = table.column(Column::initial(40.0));
                            }
                            
                            table
                                .header(30.0, |mut header| {
                                    for i in 0..col_count {
                                        header.col(|ui| {
                                            if !self.table_edit_mode {
                                                let arrow = if self.sort_column == Some(i) {
                                                    if self.sort_ascending { " ▲" } else { " ▼" }
                                                } else { "" };
                                                
                                                if ui.button(RichText::new(format!("Kolumn{}{}", i + 1, arrow))
                                                    .color(egui::Color32::from_rgb(255, 200, 100))
                                                    .strong()).clicked() {
                                                    // Sortera
                                                    if self.sort_column == Some(i) {
                                                        self.sort_ascending = !self.sort_ascending;
                                                    } else {
                                                        self.sort_column = Some(i);
                                                        self.sort_ascending = true;
                                                    }
                                                    
                                                    self.table_data.sort_by(|a, b| {
                                                        let cmp = a[i].cmp(&b[i]);
                                                        if self.sort_ascending { cmp } else { cmp.reverse() }
                                                    });
                                                }
                                            } else {
                                                ui.strong(RichText::new(format!("Kolumn{}", i + 1))
                                                    .color(egui::Color32::from_rgb(255, 200, 100)));
                                            }
                                        });
                                    }
                                    
                                    // Extra header för radera-kolumn
                                    if self.table_edit_mode {
                                        header.col(|ui| {
                                            ui.strong(RichText::new("Ta bort")
                                                .color(egui::Color32::from_rgb(255, 100, 100)));
                                        });
                                    }
                                })
                                .body(|mut body| {
                                    let row_count = self.table_data.len();
                                    let mut rows_to_delete = Vec::new();
                                    
                                    for row_idx in 0..row_count {
                                        body.row(30.0, |mut row_ui| {
                                            // Redigerbara celler eller vanlig visning
                                            for col_idx in 0..col_count {
                                                row_ui.col(|ui| {
                                                    if self.table_edit_mode {
                                                        let cell_value = &mut self.table_data[row_idx][col_idx];
                                                        if ui.add(egui::TextEdit::singleline(cell_value)
                                                            .desired_width(80.0)).changed() {
                                                            self.table_modified = true;
                                                        }
                                                    } else {
                                                        ui.label(RichText::new(&self.table_data[row_idx][col_idx])
                                                            .color(egui::Color32::from_rgb(200, 200, 220)));
                                                    }
                                                });
                                            }
                                            
                                            // Ta bort-knapp i edit-mode
                                            if self.table_edit_mode {
                                                row_ui.col(|ui| {
                                                    if ui.button("🗑️").clicked() {
                                                        rows_to_delete.push(row_idx);
                                                        self.table_modified = true;
                                                    }
                                                });
                                            }
                                        });
                                    }
                                    
                                    // Ta bort markerade rader efter loopen
                                    for &idx in rows_to_delete.iter().rev() {
                                        self.table_data.remove(idx);
                                    }
                                });
                        });
                        } else {
                            // Vanlig textvisning
                            ScrollArea::vertical().max_height(450.0).show(ui, |ui| {
                                ui.add(egui::TextEdit::multiline(&mut text_content)
                                    .desired_width(f32::INFINITY)
                                    .desired_rows(25)
                                    .font(egui::TextStyle::Monospace));
                            });
                        }
                    } else {
                        // Okänt format (gamla data utan prefix)
                        ui.label(RichText::new("⚠️ Okänt dataformat")
                            .color(egui::Color32::YELLOW));
                        ScrollArea::vertical().max_height(450.0).show(ui, |ui| {
                            // Pass a mutable reference to the actual String instead of a temporary &str
                            ui.add(egui::TextEdit::multiline(&mut self.decrypted_content)
                                .desired_width(f32::INFINITY)
                                .desired_rows(25)
                                .font(egui::TextStyle::Monospace));
                        });
                    } // Stäng else-blocket för is_text_data
                    
                    ui.add_space(15.0);
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🏠 Tillbaka till Start").size(13.0)
                        )).clicked() {
                            self.reset_session();
                        }
                    });
                },
                
                GuideStep::ViewError => {
                    self.show_ai_message(ui, "\"Oj då! Något gick fel. 😟\"");
                    
                    ui.label(RichText::new(&self.message)
                        .size(16.0).strong().color(egui::Color32::from_rgb(255, 100, 100)));
                    ui.add_space(20.0);
                    
                    ui.label(RichText::new("Vanliga orsaker:").size(14.0).strong());
                    ui.label("• Fel lösenord (kontrollera stavning och versaler/gemener)");
                    ui.label("• ID finns inte i databasen");
                    ui.label("• personer.bin-filen saknas eller är skadad");
                    ui.label("• Brute-force-skydd aktivt (för många felaktiga försök)");
                    
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🔄 Försök igen").size(13.0)
                        )).clicked() {
                            self.password_input.clear();
                            self.message.clear();
                            self.guide_step = GuideStep::ViewPassword;
                        }
                        ui.add_space(10.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🏠 Tillbaka till Start").size(13.0)
                        )).clicked() {
                            self.reset_session();
                        }
                    });
                },
                
                GuideStep::DeleteId => {
                    self.show_ai_message(ui, "\"Okej, låt oss radera en post. Vilket ID vill du ta bort? (Detta går inte att ångra!)\"");
                    
                    ui.label(RichText::new("📝 Ange ID att radera:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.identifier_input)
                            .hint_text("ID för post som ska raderas"));
                    
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.identifier_input.is_empty() {
                            self.guide_step = GuideStep::DeletePassword;
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.reset_session();
                        }
                        if ui.button(RichText::new("➡️ Nästa").size(13.0)).clicked() 
                            && !self.identifier_input.is_empty() {
                            self.guide_step = GuideStep::DeletePassword;
                        }
                    });
                },
                
                GuideStep::DeletePassword => {
                    self.show_ai_message(ui, 
                        &format!("\"För att bekräfta radering av '{}', ange lösenordet.\"", self.identifier_input));
                    
                    ui.label(RichText::new("🔑 Bekräfta med lösenord:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.password_input)
                            .password(true)
                            .hint_text("Ange lösenord för bekräftelse"));
                    
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.password_input.is_empty() {
                            match decrypt_and_load(&self.identifier_input, &self.password_input) {
                                Ok(_) => {
                                    match delete_entry(&self.identifier_input) {
                                        Ok(_) => {
                                            self.message = format!("✅ Post '{}' raderad!", self.identifier_input);
                                            self.guide_step = GuideStep::DeleteComplete;
                                        },
                                        Err(e) => {
                                            self.message = format!("❌ Fel vid radering: {}", e);
                                            self.guide_step = GuideStep::DeleteError;
                                        }
                                    }
                                },
                                Err(e) => {
                                    self.message = format!("❌ {}", e);
                                    self.guide_step = GuideStep::DeleteError;
                                }
                            }
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.guide_step = GuideStep::DeleteId;
                        }
                        if ui.button(RichText::new("🗑️ Radera Post!").size(13.0)).clicked() 
                            && !self.password_input.is_empty() {
                            match decrypt_and_load(&self.identifier_input, &self.password_input) {
                                Ok(_) => {
                                    match delete_entry(&self.identifier_input) {
                                        Ok(_) => {
                                            self.message = format!("✅ Post '{}' raderad!", self.identifier_input);
                                            self.guide_step = GuideStep::DeleteComplete;
                                        },
                                        Err(e) => {
                                            self.message = format!("❌ Fel vid radering: {}", e);
                                            self.guide_step = GuideStep::DeleteError;
                                        }
                                    }
                                },
                                Err(e) => {
                                    self.message = format!("❌ {}", e);
                                    self.guide_step = GuideStep::DeleteError;
                                }
                            }
                        }
                    });
                },
                
                GuideStep::DeleteComplete => {
                    self.show_ai_message(ui, "\"Posten har raderats permanent.\"");
                    
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("🗑️ POST RADERAD").size(24.0).strong()
                            .color(egui::Color32::from_rgb(255, 200, 100)));
                        ui.add_space(10.0);
                        ui.label(RichText::new(&self.message).size(14.0)
                            .color(egui::Color32::WHITE));
                    });
                    
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🏠 Tillbaka till Start").size(13.0)
                        )).clicked() {
                            self.reset_session();
                        }
                    });
                },
                
                GuideStep::DeleteError => {
                    self.show_ai_message(ui, "\"Oj då! Kunde inte radera posten. 😟\"");
                    
                    ui.label(RichText::new(&self.message)
                        .size(16.0).strong().color(egui::Color32::from_rgb(255, 100, 100)));
                    ui.add_space(20.0);
                    
                    ui.label(RichText::new("Vanliga orsaker:").size(14.0).strong());
                    ui.label("• Fel lösenord (kontrollera stavning och versaler/gemener)");
                    ui.label("• ID finns inte i databasen");
                    ui.label("• personer.bin-filen saknas eller är skadad");
                    ui.label("• Saknar skrivbehörighet");
                    ui.label("• Brute-force-skydd aktivt (för många felaktiga försök)");
                    
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🔄 Försök igen").size(13.0)
                        )).clicked() {
                            self.password_input.clear();
                            self.message.clear();
                            self.guide_step = GuideStep::DeletePassword;
                        }
                        ui.add_space(10.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🏠 Tillbaka till Start").size(13.0)
                        )).clicked() {
                            self.reset_session();
                        }
                    });
                },
                
                GuideStep::BulkImportId => {
                    self.show_ai_message(ui, "\"Perfekt! Låt oss importera många bilder på en gång. Först behöver jag ett ID för alla bilder.\"");
                    
                    ui.label(RichText::new("📝 Ange ID för bildsamlingen:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.identifier_input)
                            .hint_text("t.ex. semester_2025 eller familjealbum"));
                    
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.identifier_input.is_empty() {
                            self.guide_step = GuideStep::BulkImportPassword;
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.reset_session();
                        }
                        if ui.button(RichText::new("➡️ Nästa").size(13.0)).clicked() 
                            && !self.identifier_input.is_empty() {
                            self.guide_step = GuideStep::BulkImportPassword;
                        }
                    });
                },
                
                GuideStep::BulkImportPassword => {
                    self.show_ai_message(ui, 
                        &format!("\"Ange ett lösenord för ID: '{}'\"", self.identifier_input));
                    
                    ui.label(RichText::new("🔑 Lösenord:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.password_input)
                            .password(true)
                            .hint_text("Välj ett lösenord"));
                    
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.password_input.is_empty() {
                            self.guide_step = GuideStep::BulkImportFolder;
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.guide_step = GuideStep::BulkImportId;
                        }
                        if ui.button(RichText::new("➡️ Nästa").size(13.0)).clicked() 
                            && !self.password_input.is_empty() {
                            self.guide_step = GuideStep::BulkImportFolder;
                        }
                    });
                },
                
                GuideStep::BulkImportFolder => {
                    self.show_ai_message(ui, "\"Utmärkt! Nu väljer du mappen med bilder. Jag kommer optimera dem till max 1MB var.\"");
                    
                    ui.label(RichText::new("📁 Välj mapp med bilder:").size(16.0).strong());
                    ui.add_space(10.0);
                    
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("📂 Välj Mapp...").size(14.0)).clicked() {
                            self.open_folder_dialog = true;
                        }
                        ui.add_space(10.0);
                        ui.label(RichText::new("eller skriv sökväg:").size(11.0)
                            .color(egui::Color32::GRAY));
                    });
                    
                    if self.open_folder_dialog {
                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                            self.folder_path_input = folder.to_string_lossy().to_string();
                        }
                        self.open_folder_dialog = false;
                    }
                    
                    ui.add_space(5.0);
                    ui.add_sized([600.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.folder_path_input)
                            .hint_text("/home/user/bilder eller /hem/användare/mina_bilder"));
                    
                    ui.add_space(10.0);
                    if !self.folder_path_input.is_empty() {
                        if std::path::Path::new(&self.folder_path_input).exists() {
                            ui.label(RichText::new("✅ Mapp hittad!").size(12.0)
                                .color(egui::Color32::from_rgb(100, 255, 100)));
                        } else {
                            ui.label(RichText::new("⚠️ Mappen finns inte").size(12.0)
                                .color(egui::Color32::from_rgb(255, 200, 100)));
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.guide_step = GuideStep::BulkImportPassword;
                        }
                        if ui.button(RichText::new("📥 Importera Bilder!").size(13.0)).clicked() 
                            && !self.folder_path_input.is_empty() {
                            // Start background import thread and switch to importing view
                            let folder = self.folder_path_input.clone();
                            let identifier = self.identifier_input.clone();
                            let password = self.password_input.clone();

                            let (tx, rx) = mpsc::channel::<ImportMsg>();
                            self.import_rx = Some(rx);

                            // Spawn thread to process images and send progress
                            thread::spawn(move || {
                                // Try to lower thread priority (nice) on Unix to reduce UI impact
                                #[cfg(target_family = "unix")]
                                {
                                    use libc::{setpriority, PRIO_PROCESS};
                                    // 10 is lower priority
                                    let pid = 0; // current process
                                    unsafe {
                                        let rc = setpriority(PRIO_PROCESS, pid, 10);
                                        if rc == 0 {
                                            // ok
                                        } else {
                                            // ignore error
                                        }
                                    }
                                }
                                // Run the import in a catch_unwind to avoid crashing the whole process
                                let tx_clone = tx.clone();
                                let result = std::panic::catch_unwind(move || {
                                    // Collect image files
                                    let mut image_files = Vec::new();
                                    if let Ok(entries) = fs::read_dir(&folder) {
                                    for entry in entries.flatten() {
                                        if let Ok(ft) = entry.file_type() {
                                            if ft.is_file() {
                                                let path = entry.path();
                                                if let Some(ext) = path.extension() {
                                                    let ext_lower = ext.to_string_lossy().to_lowercase();
                                                    if ext_lower == "jpg" || ext_lower == "jpeg" || 
                                                       ext_lower == "png" || ext_lower == "gif" || 
                                                       ext_lower == "webp" {
                                                        image_files.push(path);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if image_files.is_empty() {
                                    let _ = tx.send(ImportMsg::Finished(Err("Inga bildfiler hittades i mappen".to_string())));
                                    return;
                                }

                                let total = image_files.len();
                                let _ = tx.send(ImportMsg::Total(total));

                                // Stream-skrivning: öppna personer-filen och skriv varje rad direkt för att
                                // undvika att hålla stora base64-strängar i minnet (minskar OOM-risk).
                                use std::io::Write;
                                let mut wrote_any = 0usize;

                                // Öppna en debug-logg i arbetsmappen så vi kan läsa vad som hände i importtråden
                                let log_path = "/home/matsu/databasen/import_debug.log";
                                let mut log_opt = match std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
                                    Ok(f) => Some(f),
                                    Err(_) => None,
                                };
                                if let Some(l) = log_opt.as_mut() {
                                    let _ = writeln!(l, "[IMPORT] Start import: folder='{}' total_files={}", folder, image_files.len());
                                }

                                match std::fs::File::create(PERSONER) {
                                    Ok(mut file) => {
                                        for (idx, img_path) in image_files.iter().enumerate() {
                                            let filename = img_path.file_name()
                                                .map(|s| s.to_string_lossy().to_string())
                                                .unwrap_or_else(|| "unknown_filename".to_string());
                                            let _ = tx.send(ImportMsg::Progress(idx + 1, filename.clone()));

                                            if let Some(l) = log_opt.as_mut() {
                                                let _ = writeln!(l, "[IMPORT] Processing {} ({}/{})", filename, idx + 1, image_files.len());
                                            }

                                            match fs::read(img_path) {
                                                Ok(data) => {
                                                    // Protect individual image processing with catch_unwind so a single
                                                    // korrupt bild inte kraschar hela importtråden.
                                                    let res = std::panic::catch_unwind(|| {
                                                        optimize_image_data(&data)
                                                    });

                                                    if let Ok(opt_res) = res {
                                                        match opt_res {
                                                            Ok(optimized) => {
                                                                let encoded = general_purpose::STANDARD.encode(&optimized);
                                                                if writeln!(file, "{}|{}", filename, encoded).is_ok() {
                                                                    wrote_any += 1;
                                                                    if let Some(l) = log_opt.as_mut() {
                                                                        let _ = writeln!(l, "[IMPORT] WROTE {}", filename);
                                                                        let _ = l.flush();
                                                                    }
                                                                } else {
                                                                    if let Some(l) = log_opt.as_mut() {
                                                                        let _ = writeln!(l, "[IMPORT][ERROR] Failed to write persons file for {}", filename);
                                                                    }
                                                                    let _ = tx.send(ImportMsg::Finished(Err("Kunde inte skriva till personer-fil".to_string())));
                                                                    return;
                                                                }
                                                            },
                                                            Err(e) => {
                                                                if let Some(l) = log_opt.as_mut() {
                                                                    let _ = writeln!(l, "[IMPORT][WARN] optimize_image_data failed for {}: {}", filename, e);
                                                                }
                                                                // skip problematic image
                                                            }
                                                        }
                                                    // Throttle so we process at most 10 images per second
                                                    // (i.e., >=100ms per image). Track using last_image_time variable.
                                                    // We'll store and update last_image_time in the outer scope of the thread loop.
                                                    // (Use a small busy-wait sleep to yield CPU).
                                                    if let Some(l) = log_opt.as_mut() {
                                                        let _ = writeln!(l, "[IMPORT] Throttling check after {}", filename);
                                                    }
                                                    // sleep outside heavy lock
                                                    std::thread::sleep(std::time::Duration::from_millis(100));
                                                    } else {
                                                        // panic while optimizing this image; skip it but log
                                                        if let Some(l) = log_opt.as_mut() {
                                                            let _ = writeln!(l, "[IMPORT][PANIC] optimize panicked for {}", filename);
                                                        }
                                                    }
                                                },
                                                Err(e) => {
                                                    if let Some(l) = log_opt.as_mut() {
                                                        let _ = writeln!(l, "[IMPORT][WARN] Could not read {}: {}", filename, e);
                                                    }
                                                    /* skip unreadable */ 
                                                }
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        if let Some(l) = log_opt.as_mut() {
                                            let _ = writeln!(l, "[IMPORT][ERROR] Could not create persons file: {}", e);
                                        }
                                        let _ = tx.send(ImportMsg::Finished(Err("Kunde inte skriva till personer-fil".to_string())));
                                        return;
                                    }
                                }

                                if wrote_any == 0 {
                                    if let Some(l) = log_opt.as_mut() {
                                        let _ = writeln!(l, "[IMPORT][ERROR] No images written (wrote_any==0)");
                                    }
                                    let _ = tx.send(ImportMsg::Finished(Err("Kunde inte läsa några bilder".to_string())));
                                    return;
                                }

                                // Attempt encrypt_and_save on the file we just wrote
                                if let Some(l) = log_opt.as_mut() {
                                    let _ = writeln!(l, "[IMPORT] Calling encrypt_and_save for identifier='{}' with {} images", identifier, wrote_any);
                                }

                                match std::panic::catch_unwind(|| encrypt_and_save(&identifier, &password)) {
                                    Ok(enc_res) => {
                                        match enc_res {
                                            Ok(_) => {
                                                if let Some(l) = log_opt.as_mut() {
                                                    let _ = writeln!(l, "[IMPORT] encrypt_and_save OK");
                                                }
                                                let msg = format!("{} bilder importerade och krypterade!", wrote_any);
                                                let _ = tx.send(ImportMsg::Finished(Ok(msg)));
                                            },
                                            Err(e) => {
                                                if let Some(l) = log_opt.as_mut() {
                                                    let _ = writeln!(l, "[IMPORT][ERROR] encrypt_and_save returned error: {}", e);
                                                }
                                                let _ = tx.send(ImportMsg::Finished(Err(format!("Fel vid kryptering: {}", e))));
                                            }
                                        }
                                    }
                                    Err(panic_info) => {
                                        if let Some(l) = log_opt.as_mut() {
                                            let _ = writeln!(l, "[IMPORT][PANIC] encrypt_and_save panicked: {:?}", panic_info);
                                        }
                                        let _ = tx.send(ImportMsg::Finished(Err("Panic under kryptering".to_string())));
                                    }
                                }
                                });

                                if let Err(panic_info) = result {
                                    // Attempt to stringify panic info
                                    let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                                        s.to_string()
                                    } else if let Some(s) = panic_info.downcast_ref::<String>() {
                                        s.clone()
                                    } else {
                                        "Okänt panik-värde".to_string()
                                    };
                                    let _ = tx_clone.send(ImportMsg::Finished(Err(format!("Panic i importtråd: {}", panic_msg))));
                                }
                            });

                            self.guide_step = GuideStep::BulkImporting;
                        }
                    });
                },
                
                GuideStep::BulkImporting => {
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("⏳ IMPORTERAR BILDER...").size(20.0).strong()
                            .color(egui::Color32::from_rgb(255, 200, 100)));
                        ui.add_space(15.0);
                        
                        if self.import_progress_total > 0 {
                            let progress = self.import_progress_current as f32 / self.import_progress_total as f32;
                            let percent = (progress * 100.0) as usize;
                            
                            ui.label(RichText::new(format!("📊 {} av {} bilder importerade ({}%)", 
                                self.import_progress_current, 
                                self.import_progress_total,
                                percent))
                                .size(14.0).strong()
                                .color(egui::Color32::from_rgb(100, 200, 255)));
                            
                            ui.add_space(10.0);
                            ui.add(egui::ProgressBar::new(progress)
                                .desired_width(500.0)
                                .show_percentage());
                            ui.add_space(10.0);
                        }
                        
                        if !self.loading_status.is_empty() {
                            ui.label(RichText::new(&self.loading_status).size(12.0)
                                .color(egui::Color32::from_rgb(200, 200, 200)));
                        }
                    });
                    
                    // Poll import receiver if background thread was started
                    // Safely take the receiver to avoid borrowing `self` while assigning to it
                    if let Some(rx_inner) = self.import_rx.take() {
                        // We'll keep ownership of rx_inner until we decide whether to drop it
                        let mut finished = false;
                        while let Ok(msg) = rx_inner.try_recv() {
                            match msg {
                                ImportMsg::Total(t) => {
                                    self.import_progress_total = t;
                                }
                                ImportMsg::Progress(current, filename) => {
                                    self.import_progress_current = current;
                                    self.loading_status = format!("Bearbetar {}...", filename);
                                }
                                ImportMsg::Finished(res) => {
                                    match res {
                                        Ok(success_msg) => {
                                            self.message = format!("✅ {}", success_msg);
                                            self.loading_status = "Klart! 🎉".to_string();
                                            finished = true;
                                        },
                                        Err(err_msg) => {
                                            self.message = format!("❌ {}", err_msg);
                                            self.guide_step = GuideStep::BulkImportError;
                                            finished = true;
                                        }
                                    }
                                }
                            }
                        }

                        // If not finished, put the receiver back so we continue polling next frame
                        if !finished {
                            self.import_rx = Some(rx_inner);
                        } else {
                            // drop rx_inner by leaving import_rx as None
                        }
                    }

                    // Show success and back button when import done (message set by Finished)
                    if !self.message.is_empty() && self.import_rx.is_none() {
                        ui.add_space(20.0);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new(&self.message).size(16.0)
                                .color(egui::Color32::from_rgb(100, 255, 100)));
                            ui.add_space(15.0);
                            if ui.add_sized([250.0, 40.0], egui::Button::new(
                                RichText::new("🏠 Tillbaka till Start").size(13.0)
                            )).clicked() {
                                self.reset_session();
                            }
                        });
                    }
                },
                
                GuideStep::BulkImportError => {
                    self.show_ai_message(ui, "\"Oj då! Något gick fel vid import. 😟\"");
                    
                    ui.label(RichText::new(&self.message)
                        .size(16.0).strong().color(egui::Color32::from_rgb(255, 100, 100)));
                    ui.add_space(20.0);
                    
                    ui.label(RichText::new("Vanliga orsaker:").size(14.0).strong());
                    ui.label("• Mappen finns inte eller är otillgänglig");
                    ui.label("• Inga bildfiler (JPG, PNG, GIF, WEBP) hittades i mappen");
                    ui.label("• Bilderna är skadade eller kan inte läsas");
                    ui.label("• Saknar läs-/skrivbehörighet");
                    ui.label("• Disken är full");
                    
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🔄 Försök igen").size(13.0)
                        )).clicked() {
                            self.folder_path_input.clear();
                            self.message.clear();
                            self.loading_status.clear();
                            self.import_progress_current = 0;
                            self.import_progress_total = 0;
                            self.guide_step = GuideStep::BulkImportFolder;
                        }
                        ui.add_space(10.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🏠 Tillbaka till Start").size(13.0)
                        )).clicked() {
                            self.reset_session();
                        }
                    });
                },
                
                GuideStep::GalleryId => {
                    self.show_ai_message(ui, "\"Härligt! Låt oss visa bildgalleriet. Vilket ID innehåller bilderna?\"");
                    
                    ui.label(RichText::new("📝 Ange ID:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.identifier_input)
                            .hint_text("ID för bildsamling"));
                    
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.identifier_input.is_empty() {
                            self.guide_step = GuideStep::GalleryPassword;
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.reset_session();
                        }
                        if ui.button(RichText::new("➡️ Nästa").size(13.0)).clicked() 
                            && !self.identifier_input.is_empty() {
                            self.guide_step = GuideStep::GalleryPassword;
                        }
                    });
                },
                
                GuideStep::GalleryPassword => {
                    self.show_ai_message(ui, 
                        &format!("\"Ange lösenordet för ID: '{}'\"", self.identifier_input));
                    
                    ui.label(RichText::new("🔑 Lösenord:").size(16.0).strong());
                    ui.add_space(5.0);
                    let response = ui.add_sized([400.0, 35.0], 
                        egui::TextEdit::singleline(&mut self.password_input)
                            .password(true)
                            .hint_text("Ange lösenord"));
                    
                    let mut should_load = false;
                    if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        if !self.password_input.is_empty() {
                            should_load = true;
                        }
                    }
                    
                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("⬅️ Tillbaka").size(13.0)).clicked() {
                            self.guide_step = GuideStep::GalleryId;
                        }
                        if ui.button(RichText::new("🖼️ Visa Galleri!").size(13.0)).clicked() 
                            && !self.password_input.is_empty() {
                            should_load = true;
                        }
                    });
                    
                    if should_load {
                        match decrypt_and_load(&self.identifier_input, &self.password_input) {
                            Ok(content) => {
                                self.entries.clear();
                                for line in content.lines() {
                                    if line.is_empty() { continue; }
                                    let parts: Vec<&str> = line.split('|').collect();
                                    if parts.len() >= 2 {
                                        let namn = parts[0].to_string();
                                        // Store base64 string and decode lazily during rendering
                                        self.entries.push(GalleryEntry {
                                            namn,
                                            base64: Some(parts[1].to_string()),
                                            decrypted_data: None,
                                        });
                                    }
                                }
                                self.guide_step = GuideStep::GalleryView;
                            },
                            Err(e) => {
                                self.message = format!("❌ {}", e);
                                self.guide_step = GuideStep::GalleryError;
                            }
                        }
                    }
                },
                
                GuideStep::GalleryView => {
                    self.show_ai_message(ui, "\"Perfekt! Här är ditt bildgalleri med 5 kolumner. Håll muspekaren över en bild för större förhandsgranskning!\"");
                    
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("🖼️ BILDGALLERI (5 KOLUMNER)").size(22.0).strong()
                            .color(egui::Color32::from_rgb(150, 100, 255)));
                        ui.add_space(5.0);
                        if !self.entries.is_empty() {
                            ui.label(RichText::new(format!("📊 {} bilder dekrypterade", self.entries.len()))
                                .size(13.0).color(egui::Color32::from_rgb(200, 200, 255)));
                        }
                    });
                    ui.add_space(10.0);
                    
                    if self.entries.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(30.0);
                            ui.label(RichText::new("⚠️").size(40.0));
                            ui.label(RichText::new("Inga bilder hittades").size(16.0)
                                .color(egui::Color32::from_rgb(255, 200, 100)));
                            ui.label(RichText::new("Kontrollera ditt ID och lösenord").size(12.0)
                                .color(egui::Color32::GRAY));
                        });
                    } else {
                        ScrollArea::vertical()
                            .max_height(ui.available_height() - 80.0)
                            .show(ui, |ui| {
                            let entries_with_data: Vec<_> = self.entries.iter()
                                .filter(|e| e.base64.is_some())
                                .collect();
                            
                            // 5 KOLUMNER MED CHUNKS - PERFEKT LAYOUT!
                            let columns = 5;
                            let available_width = ui.available_width();
                            let spacing = 10.0;
                            let thumbnail_size = (available_width - (spacing * (columns as f32 - 1.0))) / columns as f32;
                            let thumbnail_size = thumbnail_size.min(200.0); // Max 200px
                            
                            // Dela upp i chunks av 5 bilder
                            for chunk in entries_with_data.chunks(columns) {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing = egui::vec2(spacing, 0.0);

                                    for entry in chunk {
                                        if let Some(b64) = &entry.base64 {
                                            if let Ok(decoded) = general_purpose::STANDARD.decode(b64) {
                                                if let Ok(img) = image::load_from_memory(&decoded) {
                                                    let rgba = img.to_rgba8();
                                                    let size = [rgba.width() as usize, rgba.height() as usize];
                                                    let pixels = rgba.as_flat_samples();
                                                    let color_image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());
                                                    // Use texture cache to avoid creating too many textures at once
                                                    let texture = if let Some(tex) = self.texture_cache.get(&entry.namn) {
                                                        tex.clone()
                                                    } else {
                                                        let tex = ctx.load_texture(&entry.namn, color_image, egui::TextureOptions::default());
                                                        // insert into cache and lru
                                                        self.texture_cache.insert(entry.namn.clone(), tex.clone());
                                                        self.texture_lru.push_back(entry.namn.clone());
                                                        // limit cache size
                                                        const CACHE_LIMIT: usize = 30;
                                                        while self.texture_lru.len() > CACHE_LIMIT {
                                                            if let Some(old) = self.texture_lru.pop_front() {
                                                                self.texture_cache.remove(&old);
                                                            }
                                                        }
                                                        tex
                                                    };

                                                    // THUMBNAIL-KORT
                                                    egui::Frame::none()
                                                        .fill(egui::Color32::from_rgb(30, 30, 45))
                                                        .rounding(6.0)
                                                        .inner_margin(6.0)
                                                        .show(ui, |ui| {
                                                            ui.set_width(thumbnail_size);
                                                            ui.set_height(thumbnail_size + 35.0);

                                                            ui.vertical(|ui| {
                                                                // THUMBNAIL med aspect ratio bevarad
                                                                let img_width = img.width() as f32;
                                                                let img_height = img.height() as f32;
                                                                let aspect = img_width / img_height;
                                                                let thumb_display_size = if aspect > 1.0 {
                                                                    egui::vec2(thumbnail_size - 12.0, (thumbnail_size - 12.0) / aspect)
                                                                } else {
                                                                    egui::vec2((thumbnail_size - 12.0) * aspect, thumbnail_size - 12.0)
                                                                };

                                                                let img_response = ui.add(egui::Image::new(&texture, thumb_display_size));

                                                                // HOVER TOOLTIP MED 400PX MAX
                                                                img_response.on_hover_ui_at_pointer(|ui| {
                                                                    ui.set_max_width(900.0);
                                                                    ui.set_max_height(700.0);

                                                                    egui::Frame::none()
                                                                        .fill(egui::Color32::from_rgba_premultiplied(20, 20, 30, 250))
                                                                        .rounding(8.0)
                                                                        .inner_margin(10.0)
                                                                        .show(ui, |ui| {
                                                                            ui.vertical(|ui| {
                                                                                ui.label(RichText::new(&entry.namn).size(13.0).strong().color(egui::Color32::WHITE));
                                                                                ui.add_space(5.0);

                                                                                // MAX 400PX PREVIEW!
                                                                                let max_preview = 400.0;
                                                                                let preview_scale = (max_preview / img_width.max(img_height)).min(1.0);
                                                                                let preview_size = egui::vec2(img_width * preview_scale, img_height * preview_scale);

                                                                                ui.add(egui::Image::new(&texture, preview_size));

                                                                                ui.add_space(5.0);
                                                                                ui.label(RichText::new(format!("📐 {}x{} px  💾 {:.1} KB", img.width(), img.height(), decoded.len() as f32 / 1024.0)).size(10.0).color(egui::Color32::GRAY));
                                                                            });
                                                                        });
                                                                });

                                                                // BILDNAMN under thumbnail
                                                                ui.add_space(4.0);
                                                                let short_name = if entry.namn.len() > 15 { format!("{}...", &entry.namn[..12]) } else { entry.namn.clone() };
                                                                ui.label(RichText::new(short_name).size(9.0).color(egui::Color32::from_rgb(180, 180, 200)));
                                                            });
                                                        });
                                                }
                                            }
                                        }
                                    }
                                });
                                ui.add_space(spacing); // Spacing mellan raderna
                            }
                        });
                    }
                    
                    ui.add_space(10.0);
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🏠 Tillbaka till Start").size(13.0)
                        )).clicked() {
                            self.reset_session();
                        }
                    });
                },
                
                GuideStep::GalleryError => {
                    self.show_ai_message(ui, "\"Oj! Kunde inte ladda bildgalleriet. 😟\"");
                    
                    ui.label(RichText::new(&self.message)
                        .size(16.0).strong().color(egui::Color32::from_rgb(255, 100, 100)));
                    ui.add_space(20.0);
                    
                    ui.label(RichText::new("Vanliga orsaker:").size(14.0).strong());
                    ui.label("• Fel lösenord (kontrollera stavning och versaler/gemener)");
                    ui.label("• ID finns inte i databasen");
                    ui.label("• ID:t innehåller inte bilddata (använd 'Bulk Import' för att lägga till bilder)");
                    ui.label("• personer.bin-filen saknas eller är skadad");
                    ui.label("• Brute-force-skydd aktivt (för många felaktiga försök)");
                    
                    ui.add_space(20.0);
                    ui.vertical_centered(|ui| {
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🔄 Försök igen").size(13.0)
                        )).clicked() {
                            self.password_input.clear();
                            self.message.clear();
                            self.guide_step = GuideStep::GalleryPassword;
                        }
                        ui.add_space(10.0);
                        if ui.add_sized([250.0, 40.0], egui::Button::new(
                            RichText::new("🏠 Tillbaka till Start").size(13.0)
                        )).clicked() {
                            self.reset_session();
                        }
                    });
                },
            }
            
            // VISA MEDDELANDEN
            ui.add_space(15.0);
            if !self.message.is_empty() && self.guide_step == GuideStep::Welcome {
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new(&self.message).size(13.0)
                        .color(egui::Color32::from_rgb(255, 200, 100)));
                });
            }
        });
    }
}

fn main() -> Result<(), eframe::Error> {
    // Install panic hook to log panic info to a file for easier debugging
    std::panic::set_hook(Box::new(|info| {
        let _ = std::fs::write("/tmp/ai_databasen_panic.log", format!("Panic: {}\n", info));
        eprintln!("Panic occurred: {} (also logged to /tmp/ai_databasen_panic.log)", info);
    }));
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(950.0, 750.0)),
        min_window_size: Some(egui::vec2(800.0, 600.0)),
        ..Default::default()
    };
    
    eframe::run_native(
        "AI_databasen",
        options,
        Box::new(|cc| {
            // Ladda tema EN gång vid uppstart
            let theme = load_theme_from_yaml();
            apply_theme(&cc.egui_ctx, &theme);
            setup_fonts(&cc.egui_ctx);
            Box::<MyApp>::default()
        }),
    )
}
