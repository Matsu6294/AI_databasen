use eframe::egui;
use eframe::egui::{Color32, FontFamily, FontId, TextStyle};
use serde::{Deserialize, Serialize};
use std::fs;
use std::env;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Theme {
    pub bg: (u8, u8, u8),
    pub text: (u8, u8, u8),
    pub heading_size: Option<f32>,
    pub row_even: Option<(u8, u8, u8)>,
    pub row_odd: Option<(u8, u8, u8)>,
}

impl Theme {
    pub fn default() -> Self {
        Self {
            bg: (20, 20, 20),
            text: (230, 230, 235),
            heading_size: Some(18.0),
            row_even: Some((30, 30, 30)),
            row_odd: Some((24, 24, 24)),
        }
    }

    fn color32(rgb: (u8, u8, u8)) -> Color32 {
        Color32::from_rgb(rgb.0, rgb.1, rgb.2)
    }
}

/// Load theme from `desig.yaml` in current working directory or return default.
pub fn load_theme_from_yaml() -> Theme {
    // Try desig.yaml next to the running executable first, then fallback to cwd
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            let p = parent.join("desig.yaml");
            eprintln!("Trying to load theme from: {}", p.display());
            if let Ok(s) = fs::read_to_string(&p) {
                if let Ok(mut t) = serde_yaml::from_str::<Theme>(&s) {
                    if t.heading_size.is_none() { t.heading_size = Some(18.0); }
                    if t.row_even.is_none() { t.row_even = Some((30,30,30)); }
                    if t.row_odd.is_none() { t.row_odd = Some((24,24,24)); }
                    eprintln!("Successfully loaded theme: bg={:?}, text={:?}", t.bg, t.text);
                    return t;
                } else {
                    eprintln!("Failed to parse {} - will try cwd", p.display());
                }
            } else {
                eprintln!("Could not read {} - will try cwd", p.display());
            }
        }
    }

    // try current working directory
    let cwd_path = PathBuf::from("desig.yaml");
    eprintln!("Trying to load theme from cwd: {}", cwd_path.display());
    if let Ok(s) = fs::read_to_string(&cwd_path) {
        if let Ok(mut t) = serde_yaml::from_str::<Theme>(&s) {
            if t.heading_size.is_none() { t.heading_size = Some(18.0); }
            if t.row_even.is_none() { t.row_even = Some((30,30,30)); }
            if t.row_odd.is_none() { t.row_odd = Some((24,24,24)); }
            eprintln!("Successfully loaded theme from cwd: bg={:?}, text={:?}", t.bg, t.text);
            return t;
        } else {
            eprintln!("Failed to parse desig.yaml in cwd: using default theme");
        }
    } else {
        eprintln!("Could not read desig.yaml from cwd: using default theme");
    }

    eprintln!("Using default theme: bg={:?}, text={:?}", Theme::default().bg, Theme::default().text);
    Theme::default()
}

/// Setup fonts once at startup to support Nordic characters
pub fn setup_fonts(ctx: &egui::Context) {
    let font_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    ];
    for p in &font_paths {
        if let Ok(bytes) = std::fs::read(p) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert("proportional_custom".to_owned(), egui::FontData::from_owned(bytes));
            // Safely insert into families: if the family exists, prepend, otherwise create it
            if let Some(fam) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                fam.insert(0, "proportional_custom".to_owned());
            } else {
                fonts.families.insert(egui::FontFamily::Proportional, vec!["proportional_custom".to_owned()]);
            }
            ctx.set_fonts(fonts);
            break;
        }
    }
}

pub fn apply_theme(ctx: &egui::Context, theme: &Theme) {
    let mut visuals = egui::Visuals::dark();
    
    // Set main background colors - these are the important ones!
    visuals.panel_fill = Theme::color32(theme.bg);
    visuals.window_fill = Theme::color32(theme.bg);
    visuals.extreme_bg_color = Theme::color32(theme.bg);
    
    // Set widget colors
    visuals.widgets.noninteractive.bg_fill = Theme::color32(theme.bg);
    visuals.widgets.inactive.bg_fill = Theme::color32(theme.bg);
    visuals.widgets.hovered.bg_fill = Theme::color32(theme.row_even.unwrap_or((30, 30, 30)));
    visuals.widgets.active.bg_fill = Theme::color32(theme.row_odd.unwrap_or((24, 24, 24)));
    
    // Set text color
    visuals.override_text_color = Some(Theme::color32(theme.text));
    
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(theme.heading_size.unwrap_or(18.0), FontFamily::Proportional),
    );
    style.text_styles.insert(TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
    ctx.set_style(style);
}

