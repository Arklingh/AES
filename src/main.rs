#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

mod lib;
use eframe::egui::{self, ViewportBuilder, ViewportCommand};
use eframe::egui::{Layout, RichText};
use eframe::Theme;
use lib::*;
use regex::Regex;
use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use rayon::ThreadPoolBuilder;

const MIN_RES_POP_WIDTH: f32 = 150.0;
const MIN_RES_POP_HIGHT: f32 = 113.0;
const DEFAULT_BUFFER_SIZE: u32 = 128 * 1024; //128KB

fn main() {
    let rt = Runtime::new().expect("Unable to create a Runtime");

    let _enter = rt.enter();

    let options = eframe::NativeOptions {
        viewport: ViewportBuilder {
            resizable: Some(false),
            inner_size: Some(egui::vec2(550.0, 650.0)),
            maximize_button: Some(false),
            ..Default::default()
        },
        default_theme: Theme::Dark,
        ..Default::default()
    };

    let _ = eframe::run_native(
        "AES v.0.6.0",
        options,
        Box::new(|_cc| Box::<MyApp>::default()),
    );
}

#[derive(PartialEq, Debug, Copy)]
enum Algorithm {
    Aes128,
    Aes192,
    Aes256,
}

#[derive(PartialEq, Debug, Clone, Copy, Eq)]
enum Implementation {
    Software,
    Hardware,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::Aes128
    }
}

impl Clone for Algorithm {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Default, Clone, Debug)]
struct KeysStr {
    key128: String,
    key192: String,
    key256: String,
}

#[derive(Clone, Debug)]
struct KeysArr {
    key128: [u8; 16],
    key192: [u8; 24],
    key256: [u8; 32],
}

impl Default for KeysArr {
    fn default() -> Self {
        KeysArr { key128: [0; 16], key192: [0; 24], key256: [0; 32] }
    }
}

#[derive(PartialEq, Copy, Debug)]
enum Action {
    Encrypt,
    Decrypt,
}

impl Default for Action {
    fn default() -> Self {
        Action::Encrypt
    }
}

impl Clone for Action {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Debug)]
struct MyApp {
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    action: Action,
    raw_keys: KeysStr,
    keys: KeysArr,
    num_threads: usize,
    buffer_size: u32,
    result_time: Duration,
    processing: bool,
    implmentation: Implementation,
    tx: Sender<Duration>,
    rx: Receiver<Duration>,
}

impl Default for MyApp {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();

        Self {
            input_file: "".to_string(),
            output_file: "".to_string(),
            algorithm: Algorithm::Aes128,
            action: Action::Encrypt,
            raw_keys: KeysStr {
                key128: "".to_string(),
                key192: "".to_string(),
                key256: "".to_string(),
            },
            keys: KeysArr { 
                key128: [0; 16],
                key192: [0; 24],
                key256: [0; 32],
            },
            num_threads: if num_cpus::get_physical() > 2 { num_cpus::get_physical() } else { 1 },
            buffer_size: DEFAULT_BUFFER_SIZE,
            result_time: Duration::new(0, 0),
            processing: false,
            implmentation: Implementation::Software,
            tx,
            rx,
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let layout = Layout::from_main_dir_and_cross_align(
                egui::Direction::LeftToRight,
                eframe::emath::Align::Min,
            );
            let popup_id = ui.make_persistent_id("Result Popup");
            if let Ok(time) = self.rx.try_recv() {
                self.result_time = time;
                self.processing = false;
                ui.with_layout(layout, |ui| {
                    ui.memory_mut(|mem| mem.open_popup(popup_id));
                });
            }

            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("Select files").heading())
                    .highlight();
            });

            let input_button_text = egui::RichText::new("Input file...").size(14.0);
            ui.horizontal(|ui| {
                let input_button = ui.add_sized([90.0, 30.0], egui::Button::new(input_button_text));
                ui.weak("Alt+O");
                if input_button.clicked()
                    || ui.input(|i| i.modifiers.alt && i.key_pressed(egui::Key::O))
                {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.input_file = path.display().to_string();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.style_mut().wrap = Some(true);
                ui.label("Input file:");
                ui.monospace(&self.input_file);
            });

            ui.label("");

            ui.horizontal(|ui| {
                let output_button_text = egui::RichText::new("Output file...").size(14.0);
                let output_button =
                    ui.add_sized([90.0, 30.0], egui::Button::new(output_button_text));
                ui.weak("Alt+S");
                if output_button.clicked()
                    || ui.input(|i| i.modifiers.alt && i.key_pressed(egui::Key::S))
                {
                    if let Some(path) = rfd::FileDialog::new().save_file() {
                        self.output_file = path.display().to_string();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.style_mut().wrap = Some(true);
                ui.label("Output file:");
                ui.monospace(&self.output_file);
            });

            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("Select options").heading())
                    .highlight();

                ui.label("");

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label("Select the algorithm");
                        egui::ComboBox::from_label(format!(""))
                            .selected_text(format!("{:?}", self.algorithm))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.algorithm,
                                    Algorithm::Aes128,
                                    "AES-128",
                                );
                                ui.selectable_value(
                                    &mut self.algorithm,
                                    Algorithm::Aes192,
                                    "AES-192",
                                );
                                ui.selectable_value(
                                    &mut self.algorithm,
                                    Algorithm::Aes256,
                                    "AES-256",
                                );
                            });
                    });

                    for _ in 0..10 {
                        ui.vertical(|_| {});
                    }
                    
                    ui.vertical(|ui| {
                        ui.label("Choose action:");
                        ui.radio_value(&mut self.action, Action::Encrypt, "Encrypt");
                        ui.radio_value(&mut self.action, Action::Decrypt, "Decrypt");
                    });
                });

                ui.label("");

                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("Input keys").heading())
                        .highlight();
                });

                if self.algorithm == Algorithm::Aes128 {
                    ui.vertical(|ui| {
                        ui.label("Enter the key(32-digit hex number):");
                        let key = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key128)
                                .hint_text("Key")
                                .desired_width(f32::INFINITY),
                        );
                        if key.changed() {
                            if !check_hex_input(&self.raw_keys.key128, 128)
                                || self.raw_keys.key128.len() > 32
                            {
                                self.raw_keys.key128 = self
                                    .raw_keys
                                    .key128
                                    .chars()
                                    .filter(|c| check_hex_input(&c.to_string(), 128))
                                    .collect();
                            }
                            if self.raw_keys.key128.len() > 32 {
                                self.raw_keys.key128.truncate(32);
                            }
                        }
                    });
                } else if self.algorithm == Algorithm::Aes192 {
                    ui.vertical(|ui| {
                        ui.label("Enter the key(48-digit hex number):");
                        let key = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key192)
                                .hint_text("Key")
                                .desired_width(f32::INFINITY),
                        );
                        if key.changed() {
                            if !check_hex_input(&self.raw_keys.key192, 192)
                                || self.raw_keys.key192.len() > 48
                            {
                                self.raw_keys.key192 = self
                                    .raw_keys
                                    .key192
                                    .chars()
                                    .filter(|c| check_hex_input(&c.to_string(), 192))
                                    .collect();
                            }
                            if self.raw_keys.key192.len() > 48 {
                                self.raw_keys.key192.truncate(48);
                            }
                        }
                    });
                } else if self.algorithm == Algorithm::Aes256 {
                    ui.vertical(|ui| {
                        ui.label("Enter the key(64-digit hex number):");
                        let key = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key256)
                                .hint_text("Key")
                                .desired_width(f32::INFINITY),
                        );
                        if key.changed() {
                            if !check_hex_input(&self.raw_keys.key256, 256)
                                || self.raw_keys.key256.len() > 64
                            {
                                self.raw_keys.key256 = self
                                    .raw_keys
                                    .key256
                                    .chars()
                                    .filter(|c| check_hex_input(&c.to_string(), 256))
                                    .collect();
                            }
                            if self.raw_keys.key256.len() > 64 {
                                self.raw_keys.key256.truncate(64);
                            }
                        }
                    });
                };

            });

            ui.label("");
            ui.label(format!("Number of CPU cores - {}", num_cpus::get_physical()));
            ui.label("");

            ui.label("Select a number of threads to be used");
            let max_threads = num_cpus::get();
            let thread_range = if max_threads > 1 {
                1..=max_threads - 1
            } else {
                1..=1 
            };
            ui.add(egui::Slider::new(
                &mut self.num_threads,
                thread_range,
            ));

            ui.label("Select buffer size(in KB):");
            let mut buffer_sizes = vec![];
            let mut size = 4 * 1024;
            while size <= 4096 * 1024 {
                buffer_sizes.push(size);
                size *= 2;
            }

            // Convert buffer sizes to KB for display in the dropdown
            let buffer_options: Vec<String> = buffer_sizes.iter().map(|&size| format!("{} KB", size / 1024)).collect();

            // Get the current buffer size index, or default to the starting size if not found
            let mut selected_index = buffer_sizes.iter().position(|&x| x == self.buffer_size).unwrap_or(0);

            // Display a combo box for buffer size selection
            egui::ComboBox::from_label("Buffer Size")
                .selected_text(&buffer_options[selected_index])
                .show_ui(ui, |ui| {
                    for (index, label) in buffer_options.iter().enumerate() {
                        if ui.selectable_value(&mut selected_index, index, label).clicked() {
                            self.buffer_size = buffer_sizes[selected_index];
                        }
                    }
                });
                                  
            ui.label("\n");

            ui.horizontal(|ui| {
                let keys_are_empty = (self.raw_keys.key128.is_empty() && self.algorithm == Algorithm::Aes128 || self.raw_keys.key192.is_empty() && self.algorithm == Algorithm::Aes192 || self.raw_keys.key256.is_empty() && self.algorithm == Algorithm::Aes256)
                    || (!check_len(&self.raw_keys.key128, self.algorithm) && self.algorithm == Algorithm::Aes128 || !check_len(&self.raw_keys.key192, self.algorithm) && self.algorithm == Algorithm::Aes192 || !check_len(&self.raw_keys.key256, self.algorithm) && self.algorithm == Algorithm::Aes256)
                    ;

                let essential_params_are_empty =
                    keys_are_empty || self.input_file.is_empty() || self.output_file.is_empty();

                let keys_valid = !essential_params_are_empty;

                let start_button_text = egui::RichText::new("Start").size(15.0);
                let start_button = ui.add_enabled(
                    keys_valid && !self.processing,
                    egui::Button::new(start_button_text)
                        .min_size(eframe::epaint::Vec2 { x: 90.0, y: 30.0 })
                        .shortcut_text("Ctrl+S"),
                );
                
                ui.label("                                                                                                          ");

                let exit_button_text = egui::RichText::new("Exit").size(15.0);
                let exit_button = ui.add_enabled(
                    !self.processing,
                    egui::Button::new(exit_button_text)
                        .min_size(eframe::epaint::Vec2 { x: 90.0, y: 30.0 })
                        .shortcut_text("Ctrl+E"),
                );
                ui.label("\n");
                let pos = egui::AboveOrBelow::Below;

                if start_button.clicked() || ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::S)) && self.processing == false {
                    
                    self.processing = true;
                    match self.algorithm {
                        Algorithm::Aes128 => self.keys.key128 =  parse_128_key(&self.raw_keys.key128).unwrap(),
                        Algorithm::Aes192 => self.keys.key192 =  parse_192_key(&self.raw_keys.key192).unwrap(),
                        Algorithm::Aes256 => self.keys.key256 =  parse_256_key(&self.raw_keys.key256).unwrap(),
                    }

                    if keys_valid {
                        send(
                            self.input_file.clone(),
                            self.output_file.clone(),
                            self.algorithm.clone(),
                            self.action.clone(),
                            self.implmentation.clone(),
                            self.keys.clone(),
                            self.num_threads.clone(),
                            self.buffer_size,
                            self.tx.clone(),
                            ctx.clone(),
                        );
                    }
                };

                if exit_button.clicked() || ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::E)) {
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }

                let result_box = RichText::new(format!(
                    "Time spent encrypting/decrypting: {}.{:03} seconds",
                    self.result_time.as_secs(),
                    self.result_time.subsec_millis(),
                ));

                egui::containers::popup::popup_above_or_below_widget(
                    &ui,
                    popup_id,
                    &start_button,
                    pos,
                    |ui| {
                        ui.set_min_width(MIN_RES_POP_WIDTH);
                        ui.set_min_height(MIN_RES_POP_HIGHT);
                        ui.label(result_box);
                    },
                );

            });
        });
    }
}

fn send(
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    action: Action,
    implem: Implementation,
    keys: KeysArr,
    num_threads: usize,
    buffer_size: u32,
    tx: Sender<Duration>,
    ctx: egui::Context,
) {
        tokio::task::spawn_blocking(move || {
            let res = process(
                input_file,
                output_file,
                algorithm,
                action,
                implem,
                keys,
                num_threads,
                buffer_size,
            );
             
            if let Err(e) = tx.send(res) {
                panic!("Error sending result through channel: {}", e);
            };

            ctx.request_repaint();
        });
    
}

fn process(
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    action: Action,
    implem: Implementation,
    keys: KeysArr,
    num_threads: usize,
    buffer_size: u32,
) -> Duration {
    let input_file = File::open(&input_file).expect("Error opening input file");
    let mut reader = BufReader::with_capacity(buffer_size as usize, input_file);
    let mut buffer = vec![0; buffer_size as usize];

    let threadpool = ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();

    let output_file = Arc::new(Mutex::new(
        OpenOptions::new()
            .write(true)
            .create(true)
            .open(&output_file)
            .expect("Failed to open output file"),
    ));
    let start_time = Instant::now();

    let keys = Arc::new(keys);
    let tasks_count = Arc::new(AtomicUsize::new(0));
    let mut chunk_index = 0;

    while let Ok(size) = reader.read(&mut buffer) {
        if size == 0 {
            break;
        }

        let mut input_data = Vec::with_capacity(size);
        input_data.extend_from_slice(&buffer[..size]);

        let chunk_keys = Arc::clone(&keys);
        let output = Arc::clone(&output_file);
        let task_count = Arc::clone(&tasks_count);
        let current_index = chunk_index;
        let is_last_chunk = size < buffer_size as usize;

        // Padding size and padded flag
        let (mut padding_size, padded) = if action == Action::Encrypt && is_last_chunk {
            let padding = 16 - (size % 16);
            if padding != 16 {
                (padding, true)
            } else {
                (0, false)
            }
        } else {
            (0, false)
        };

        task_count.fetch_add(1, Ordering::SeqCst);
        threadpool.spawn(move || {
            let mut chunk_result;

            if action == Action::Encrypt {
                let mut padded_data = input_data.clone();
                if padded {
                    padded_data.extend(vec![padding_size as u8; padding_size]);
                }
                chunk_result = match algorithm {
                    Algorithm::Aes128 => aes_128(implem, action, padded_data, chunk_keys.key128),
                    Algorithm::Aes192 => aes_192(implem, action, padded_data, chunk_keys.key192),
                    Algorithm::Aes256 => aes_256(implem, action, padded_data, chunk_keys.key256),
                };
            } else {
                if is_last_chunk {
                    padding_size = input_data.pop().unwrap_or(0) as usize;
                }
                
                chunk_result = match algorithm {
                    Algorithm::Aes128 => aes_128(implem, action, input_data.clone(), chunk_keys.key128),
                    Algorithm::Aes192 => aes_192(implem, action, input_data.clone(), chunk_keys.key192),
                    Algorithm::Aes256 => aes_256(implem, action, input_data.clone(), chunk_keys.key256),
                };

                if is_last_chunk {
                    chunk_result.truncate(chunk_result.len() - padding_size);
                }
            }

            if padded {
                chunk_result.push(padding_size as u8);
            }
            
            // Write the result to the output file
            let mut file = output.lock().unwrap();
            file.seek(SeekFrom::Start((current_index * buffer_size) as u64))
                .expect("Failed to seek in output file");
            file.write_all(&chunk_result).expect("Failed to write to output file");
            
            task_count.fetch_sub(1, Ordering::SeqCst);
        });

        chunk_index += 1;
    }

    // Wait for all tasks to complete
    while tasks_count.load(Ordering::SeqCst) > 0 {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    start_time.elapsed()
}

/// Collects a key_str String variable and returns a 32-digit hex Key.
///
/// # Arguments
///
/// * `key_str` - The key as a 16-character hexadecimal string.
///
/// # Returns
///
/// A `Result` containing a vector of Keys if successful, otherwise an error message.
fn parse_128_key(key_str: &String) -> Result<[u8; 16], &'static str> {
    let mut key = [0; 16];

    if key_str.len() == 32 {
        for (i, chunk) in key_str.as_bytes().chunks(2).enumerate() {
            key[i] = u8::from_str_radix(std::str::from_utf8(chunk).expect("Invalid UTF-8"), 16)
                .expect("Invalid hex format");
        }
        Ok(key)
    } else {
        Err("Key must be a valid 32-character hexadecimal string!")
    }
}

fn parse_192_key(key_str: &String) -> Result<[u8; 24], &'static str> {
    let mut key = [0; 24];

    if key_str.len() == 48 {
        for (i, chunk) in key_str.as_bytes().chunks(2).enumerate() {
            key[i] = u8::from_str_radix(std::str::from_utf8(chunk).expect("Invalid UTF-8"), 16)
                .expect("Invalid hex format");
        }
        Ok(key)
    } else {
        Err("Key must be a valid 48-character hexadecimal string for AES-192!")
    }
}

fn parse_256_key(key_str: &String) -> Result<[u8; 32], &'static str> {
    let mut key = [0; 32];

    if key_str.len() == 64 {
        for (i, chunk) in key_str.as_bytes().chunks(2).enumerate() {
            key[i] = u8::from_str_radix(std::str::from_utf8(chunk).expect("Invalid UTF-8"), 16)
                .expect("Invalid hex format");
        }
        Ok(key)
    } else {
        Err("Key must be a valid 64-character hexadecimal string for AES-256!")
    }
}

#[inline(always)]
fn aes_128(implem: Implementation, action: Action, input: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    let result = match (implem, action) {
        (Implementation::Software, Action::Encrypt) => aes_128_encrypt(&input, key),
        (Implementation::Software, Action::Decrypt) => aes_128_decrypt(&input, key),
        (Implementation::Hardware, Action::Encrypt) => aes_ni_128_encrypt(&input, key), 
        (Implementation::Hardware, Action::Decrypt) => aes_ni_128_decrypt(&input, key),
    };
    result  
}

fn aes_192(implem: Implementation, action: Action, input: Vec<u8>, key: [u8; 24]) -> Vec<u8> {
    let result = match (implem, action) {
        (Implementation::Software, Action::Encrypt) => aes_192_encrypt(&input, key),
        (Implementation::Software, Action::Decrypt) => aes_192_decrypt(&input, key),
        (Implementation::Hardware, Action::Encrypt) => aes_ni_192_encrypt(&input, key),
        (Implementation::Hardware, Action::Decrypt) => unimplemented!(),
    };
    result  
}

fn aes_256(implem: Implementation, action: Action, input: Vec<u8>, key: [u8; 32] ) -> Vec<u8> {
    let result = match (implem, action) {
        (Implementation::Software, Action::Encrypt) => aes_256_encrypt(&input, key),
        (Implementation::Software, Action::Decrypt) => aes_256_decrypt(&input, key),
        (Implementation::Hardware, Action::Encrypt) => unimplemented!(),
        (Implementation::Hardware, Action::Decrypt) => unimplemented!(),
    };
    result  
}

fn check_hex_input(input: &String, length: usize) -> bool {
    let max_length = match length {
        128 => 16,
        192 => 24,
        256 => 32,
        _ => return false, // Invalid length
    };

    let hex_pattern = Regex::new(&format!(r"^[0-9A-Fa-f]{{1,{}}}$", max_length))
        .expect("Couldn't generate regex!");

    hex_pattern.is_match(&input.trim())
}

fn check_len(input: &String, algorithm: Algorithm) -> bool {
    match algorithm {
        Algorithm::Aes128 => {
            if input.len() < 32 {
                false
            } else {
                true
            }
        }
        Algorithm::Aes192 => {
            if input.len() < 48 {
                false
            } else {
                true
            }
        }
        Algorithm::Aes256 => {
            if input.len() < 64 {
                false
            } else {
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plotters::prelude::*;
    use std::time::Duration;

    // Constant file names
    const INPUT_FILE: &str = "./input/1GB.bin";
    const OUTPUT_FILE: &str = "output.txt";

    /// Function to run benchmarks with varying thread counts
    fn benchmark_process(
        algorithm: Algorithm,
        action: Action,
        implem: Implementation,
        keys: KeysArr,
        buffer_size: u32,
    ) -> Vec<(usize, Duration)> {
        let mut results = Vec::new();

        for num_threads in 1..16 {
            let duration = process(
                INPUT_FILE.to_string(),
                OUTPUT_FILE.to_string(),
                algorithm,
                action,
                implem,
                keys.clone(),
                num_threads,
                buffer_size,
            );
            results.push((num_threads, duration));
        }

        results
    }

    fn plot_results(results: &[(usize, Duration)]) -> Result<(), Box<dyn std::error::Error>> {
        let root = BitMapBackend::new("encryption_time_plot.png", (1920, 1080)).into_drawing_area();
        root.fill(&WHITE)?;

        let max_time = results
            .iter()
            .map(|&(_, dur)| dur.as_millis())
            .max()
            .unwrap_or(0);

        let mut chart = ChartBuilder::on(&root)
            .caption("Encryption Time vs. Number of Threads", ("sans-serif", 60)) // Збільшено розмір заголовка
            .margin(20)
            .x_label_area_size(80) // Збільшено розмір області для підпису осі X
            .y_label_area_size(90) // Збільшено розмір області для підпису осі Y
            .build_cartesian_2d(1..15, 1..max_time)?;

        chart
            .configure_mesh()
            .x_desc("Number of Threads")
            .y_desc("Time (ms)")
            .axis_desc_style(("sans-serif", 28)) // Збільшено розмір підписів осей
            .label_style(("sans-serif", 24)) // Збільшено розмір міток на осях
            .draw()?;

        chart
            .draw_series(LineSeries::new(
                results
                    .iter()
                    .map(|&(threads, duration)| (threads as i32, duration.as_millis())),
                &RED,
            ))?
            .label("Time (ms)")
            .legend(|(x, y)| PathElement::new([(x, y), (x + 20, y)], &RED));

        chart
            .configure_series_labels()
            .background_style(&WHITE.mix(0.8))
            .border_style(&BLACK)
            // .label_style(("sans-serif", 24)) // Збільшено розмір підписів серій
            .draw()?;

        Ok(())
    }

    #[test]
    pub fn test_benchmarking_and_plotting() {
        let algorithm = Algorithm::Aes128;
        let action = Action::Encrypt;
        let implem = Implementation::Software;
        let keys = KeysArr {
            key128: [0u8; 16],
            key192: [0u8; 24],
            key256: [0u8; 32],
        };
        let buffer_size = DEFAULT_BUFFER_SIZE;

        // Run the benchmarking process
        let results = benchmark_process(algorithm, action, implem, keys, buffer_size);
        dbg!(&results);

        // Plot the results
        if let Err(e) = plot_results(&results) {
            eprintln!("Error plotting results: {}", e);
        }
    }
}

