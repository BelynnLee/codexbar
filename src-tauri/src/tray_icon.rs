use codexbar_engine::{IconMetric, MenuBarConfig, MenuBarDisplayMode};
use std::f64::consts::{FRAC_PI_2, TAU};
use tauri::image::Image;

const SIZE: u32 = 32;
const TRANSPARENT: [u8; 4] = [0, 0, 0, 0];
const ACCENT: [u8; 4] = [189, 82, 37, 255];
const GLYPH: [u8; 4] = [255, 248, 239, 255];
const TRACK: [u8; 4] = [116, 107, 96, 150];
const NORMAL: [u8; 4] = [56, 155, 118, 255];
const AMBER: [u8; 4] = [224, 173, 60, 255];
const RED: [u8; 4] = [229, 72, 77, 255];

const DIGITS: [[u8; 5]; 10] = [
    [0b111, 0b101, 0b101, 0b101, 0b111],
    [0b010, 0b110, 0b010, 0b010, 0b111],
    [0b111, 0b001, 0b111, 0b100, 0b111],
    [0b111, 0b001, 0b111, 0b001, 0b111],
    [0b101, 0b101, 0b111, 0b001, 0b001],
    [0b111, 0b100, 0b111, 0b001, 0b111],
    [0b111, 0b100, 0b111, 0b101, 0b111],
    [0b111, 0b001, 0b010, 0b010, 0b010],
    [0b111, 0b101, 0b111, 0b101, 0b111],
    [0b111, 0b101, 0b111, 0b001, 0b111],
];
const PERCENT: [u8; 5] = [0b100, 0b000, 0b010, 0b000, 0b001];

pub fn render(config: &MenuBarConfig, metric: Option<&IconMetric>) -> Image<'static> {
    let mut pixels = vec![0_u8; (SIZE * SIZE * 4) as usize];
    for pixel in pixels.chunks_exact_mut(4) {
        pixel.copy_from_slice(&TRANSPARENT);
    }
    let percent = metric.map_or(0.0, |metric| normalized_percent(metric.used_percent));
    let color = metric.map_or(ACCENT, |_| severity_color(percent));
    match config.display_mode {
        MenuBarDisplayMode::Icon => {
            draw_progress_ring(&mut pixels, percent, color);
            draw_codex_glyph(&mut pixels, 16, 16, 8, ACCENT);
        }
        MenuBarDisplayMode::Percentage => {
            if metric.is_some() {
                draw_number(
                    &mut pixels,
                    percent.round() as u8,
                    2,
                    config.show_percentage,
                    color,
                    0,
                    SIZE as i32,
                );
            } else {
                draw_codex_glyph(&mut pixels, 16, 16, 11, ACCENT);
            }
        }
        MenuBarDisplayMode::IconAndPercentage => {
            draw_codex_glyph(&mut pixels, 7, 16, 5, ACCENT);
            if metric.is_some() {
                draw_number(
                    &mut pixels,
                    percent.round() as u8,
                    1,
                    config.show_percentage,
                    color,
                    13,
                    SIZE as i32,
                );
            }
        }
    }
    Image::new_owned(pixels, SIZE, SIZE)
}

fn normalized_percent(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 100.0)
    } else {
        0.0
    }
}

fn severity_color(percent: f64) -> [u8; 4] {
    if percent >= 90.0 {
        RED
    } else if percent >= 75.0 {
        AMBER
    } else {
        NORMAL
    }
}

fn put_pixel(pixels: &mut [u8], x: i32, y: i32, color: [u8; 4]) {
    if !(0..SIZE as i32).contains(&x) || !(0..SIZE as i32).contains(&y) {
        return;
    }
    let index = ((y as u32 * SIZE + x as u32) * 4) as usize;
    if let Some(pixel) = pixels.get_mut(index..index + 4) {
        pixel.copy_from_slice(&color);
    }
}

fn draw_glyph(
    pixels: &mut [u8],
    rows: &[u8; 5],
    origin_x: i32,
    origin_y: i32,
    scale: i32,
    color: [u8; 4],
) {
    for (row, bits) in rows.iter().enumerate() {
        for column in 0..3 {
            if bits & (1 << (2 - column)) == 0 {
                continue;
            }
            for dy in 0..scale {
                for dx in 0..scale {
                    put_pixel(
                        pixels,
                        origin_x + column * scale + dx,
                        origin_y + row as i32 * scale + dy,
                        color,
                    );
                }
            }
        }
    }
}

fn draw_number(
    pixels: &mut [u8],
    value: u8,
    scale: i32,
    show_percentage: bool,
    color: [u8; 4],
    left: i32,
    right: i32,
) {
    let digits = value.to_string();
    let glyph_width = 3 * scale;
    let gap = scale;
    let digit_width =
        digits.len() as i32 * glyph_width + digits.len().saturating_sub(1) as i32 * gap;
    let percent_width = if show_percentage {
        gap + glyph_width
    } else {
        0
    };
    let total_width = digit_width + percent_width;
    let mut x = left + ((right - left - total_width) / 2).max(0);
    let y = (SIZE as i32 - 5 * scale) / 2;
    for digit in digits.bytes() {
        draw_glyph(pixels, &DIGITS[(digit - b'0') as usize], x, y, scale, color);
        x += glyph_width + gap;
    }
    if show_percentage {
        draw_glyph(pixels, &PERCENT, x, y, scale, color);
    }
}

fn draw_codex_glyph(pixels: &mut [u8], center_x: i32, center_y: i32, radius: i32, color: [u8; 4]) {
    let outer = radius * radius;
    let inner_radius = (radius - 3).max(1);
    let inner = inner_radius * inner_radius;
    for y in center_y - radius..=center_y + radius {
        for x in center_x - radius..=center_x + radius {
            let dx = x - center_x;
            let dy = y - center_y;
            let distance = dx * dx + dy * dy;
            let open_right = dx > 0 && dy.abs() < (radius / 2).max(1);
            if distance <= outer && distance >= inner && !open_right {
                put_pixel(pixels, x, y, color);
            }
        }
    }
    put_pixel(pixels, center_x - radius / 3, center_y, GLYPH);
}

fn draw_progress_ring(pixels: &mut [u8], percent: f64, color: [u8; 4]) {
    let center = 16_i32;
    for y in 1..31_i32 {
        for x in 1..31_i32 {
            let dx = x - center;
            let dy = y - center;
            let distance = dx * dx + dy * dy;
            if !(13 * 13..=15 * 15).contains(&distance) {
                continue;
            }
            put_pixel(pixels, x, y, TRACK);
            let angle = (f64::from(dy).atan2(f64::from(dx)) + FRAC_PI_2).rem_euclid(TAU);
            if angle / TAU <= percent / 100.0 {
                put_pixel(pixels, x, y, color);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codexbar_engine::{IconMetric, MenuBarConfig, MenuBarDisplayMode, ProviderId};
    use sha2::{Digest, Sha256};

    #[test]
    fn every_display_mode_produces_a_valid_32_pixel_rgba_image() {
        for mode in [
            MenuBarDisplayMode::Icon,
            MenuBarDisplayMode::Percentage,
            MenuBarDisplayMode::IconAndPercentage,
        ] {
            let mut config = MenuBarConfig::default();
            config.display_mode = mode;
            let image = render(&config, Some(&metric(82.0)));
            assert_eq!(image.width(), 32);
            assert_eq!(image.height(), 32);
            assert_eq!(image.rgba().len(), 32 * 32 * 4);
        }
    }

    #[test]
    fn display_modes_have_distinct_pixel_buffers() {
        let buffers = [
            MenuBarDisplayMode::Icon,
            MenuBarDisplayMode::Percentage,
            MenuBarDisplayMode::IconAndPercentage,
        ]
        .map(|mode| {
            let mut config = MenuBarConfig::default();
            config.display_mode = mode;
            render(&config, Some(&metric(82.0))).rgba().to_vec()
        });

        assert_ne!(buffers[0], buffers[1]);
        assert_ne!(buffers[0], buffers[2]);
        assert_ne!(buffers[1], buffers[2]);
    }

    #[test]
    fn severity_boundaries_are_normal_amber_and_red() {
        assert_eq!(severity_color(74.0), NORMAL);
        assert_eq!(severity_color(75.0), AMBER);
        assert_eq!(severity_color(89.9), AMBER);
        assert_eq!(severity_color(90.0), RED);
    }

    #[test]
    fn percentages_are_clamped_before_rendering() {
        let mut config = MenuBarConfig::default();
        config.display_mode = MenuBarDisplayMode::Percentage;
        assert_eq!(
            render(&config, Some(&metric(-10.0))).rgba(),
            render(&config, Some(&metric(0.0))).rgba(),
        );
        assert_eq!(
            render(&config, Some(&metric(140.0))).rgba(),
            render(&config, Some(&metric(100.0))).rgba(),
        );
    }

    #[test]
    fn hiding_the_percent_sign_keeps_visible_digits() {
        let mut with_percent = MenuBarConfig::default();
        with_percent.display_mode = MenuBarDisplayMode::Percentage;
        let mut digits_only = with_percent.clone();
        digits_only.show_percentage = false;
        let with_percent = render(&with_percent, Some(&metric(82.0)));
        let digits_only = render(&digits_only, Some(&metric(82.0)));
        let opaque = |image: &tauri::image::Image<'_>| {
            image
                .rgba()
                .chunks_exact(4)
                .filter(|pixel| pixel[3] != 0)
                .count()
        };

        assert_ne!(with_percent.rgba(), digits_only.rgba());
        assert!(opaque(&digits_only) > 0);
        assert!(opaque(&with_percent) > opaque(&digits_only));
    }

    #[test]
    fn identical_inputs_have_identical_sha256_pixels() {
        let mut config = MenuBarConfig::default();
        config.display_mode = MenuBarDisplayMode::IconAndPercentage;
        let first = render(&config, Some(&metric(82.0)));
        let second = render(&config, Some(&metric(82.0)));

        let first_hash = Sha256::digest(first.rgba());
        let second_hash = Sha256::digest(second.rgba());
        assert_eq!(first_hash, second_hash);
        assert_eq!(
            format!("{first_hash:x}"),
            "a74e562dd77fc08bbd1cf2e2201a25b8015a2a11a02f810d761c25fcd1540d09"
        );
    }

    fn metric(used_percent: f64) -> IconMetric {
        IconMetric {
            provider: ProviderId::Claude,
            provider_name: "Claude".to_owned(),
            account_id: "acc_test".to_owned(),
            account_label: None,
            used_percent,
        }
    }
}
