#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

mod lib;
use eframe::egui::{self, ViewportBuilder, ViewportCommand};
use eframe::egui::{Layout, RichText};
use eframe::Theme;
use lib::*;
use regex::Regex;
use std::arch::is_x86_feature_detected;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;
use rayon::ThreadPoolBuilder;

const MIN_RES_POP_WIDTH: f32 = 150.0;
const MIN_RES_POP_HIGHT: f32 = 113.0;
const CHUNK_SIZE: usize = 128 * 1024; //128KB

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
        "AES v.0.1.0",
        options,
        Box::new(|_cc| Box::<MyApp>::default()),
    );
}

#[derive(PartialEq, Copy, Debug)]
enum Mode {
    ECB,
    CBC,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::ECB
    }
}

impl Clone for Mode {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(PartialEq, Debug, Copy)]
enum Algorithm {
    AES_128,
    AES_192,
    AES_256,
}

#[derive(PartialEq, Debug)]
enum Implementation {
    Software,
    Hardware,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::AES_128
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
    mode: Mode,
    action: Action,
    raw_keys: KeysStr,
    keys: KeysArr,
    raw_iv: String,
    iv: [u8; 16],
    num_threads: usize,
    result_time: Duration,
    asnc: bool,
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
            algorithm: Algorithm::AES_128,
            mode: Mode::ECB,
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
            raw_iv: "".to_string(),
            iv: [0; 16],
            num_threads: num_cpus::get_physical(),
            result_time: Duration::new(0, 0),
            asnc: false,
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
                                    Algorithm::AES_128,
                                    "AES-128",
                                );
                                ui.selectable_value(
                                    &mut self.algorithm,
                                    Algorithm::AES_192,
                                    "AES-192",
                                );
                                ui.selectable_value(
                                    &mut self.algorithm,
                                    Algorithm::AES_256,
                                    "AES-256",
                                );
                            });
                    });
                    ui.vertical(|ui| {
                        ui.label("\nChoose execution mode:");
                        ui.radio_value(&mut self.mode, Mode::ECB, "ECB");
                        ui.radio_value(&mut self.mode, Mode::CBC, "CBC");
                    });

                    ui.vertical(|ui| {
                        ui.label("\nChoose action:");
                        ui.radio_value(&mut self.action, Action::Encrypt, "Encrypt");
                        ui.radio_value(&mut self.action, Action::Decrypt, "Decrypt");
                    });
                });

                ui.label("");

                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("Input keys").heading())
                        .highlight();
                });

                if self.algorithm == Algorithm::AES_128 {
                    ui.vertical(|ui| {
                        ui.label("Enter the key(32-digit hex number):");
                        let key = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key128)
                                .hint_text("Key")
                                .desired_width(f32::INFINITY),
                        );
                        if key.changed() {
                            if !check_hex_input_128(&self.raw_keys.key128)
                                || self.raw_keys.key128.len() > 32
                            {
                                self.raw_keys.key128 = self
                                    .raw_keys
                                    .key128
                                    .chars()
                                    .filter(|c| check_hex_input_128(&c.to_string()))
                                    .collect();
                            }
                            if self.raw_keys.key128.len() > 32 {
                                self.raw_keys.key128.truncate(32);
                            }
                        }
                    });
                } else if self.algorithm == Algorithm::AES_192 {
                    ui.vertical(|ui| {
                        ui.label("Enter the key(48-digit hex number):");
                        let key = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key192)
                                .hint_text("Key")
                                .desired_width(f32::INFINITY),
                        );
                        if key.changed() {
                            if !check_hex_input_192(&self.raw_keys.key192)
                                || self.raw_keys.key192.len() > 48
                            {
                                self.raw_keys.key192 = self
                                    .raw_keys
                                    .key192
                                    .chars()
                                    .filter(|c| check_hex_input_192(&c.to_string()))
                                    .collect();
                            }
                            if self.raw_keys.key192.len() > 48 {
                                self.raw_keys.key192.truncate(48);
                            }
                        }
                    });
                } else if self.algorithm == Algorithm::AES_256 {
                    ui.vertical(|ui| {
                        ui.label("Enter the key(64-digit hex number):");
                        let key = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key256)
                                .hint_text("Key")
                                .desired_width(f32::INFINITY),
                        );
                        if key.changed() {
                            if !check_hex_input_192(&self.raw_keys.key256)
                                || self.raw_keys.key256.len() > 64
                            {
                                self.raw_keys.key256 = self
                                    .raw_keys
                                    .key256
                                    .chars()
                                    .filter(|c| check_hex_input_256(&c.to_string()))
                                    .collect();
                            }
                            if self.raw_keys.key256.len() > 64 {
                                self.raw_keys.key256.truncate(64);
                            }
                        }
                    });
                };

                if self.mode == Mode::ECB {
                } else if self.mode == Mode::CBC {
                    ui.vertical(|ui| {
                        ui.label("\nEnter the IV(16-digit hex number):");
                        let iv_key = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_iv)
                                .hint_text("IV")
                                .desired_width(f32::INFINITY),
                        );
                        if iv_key.changed() {
                            if !check_hex_input(&self.raw_iv) || self.raw_iv.len() > 16 {
                                self.raw_iv = self
                                    .raw_iv
                                    .chars()
                                    .filter(|c| check_hex_input(&c.to_string()))
                                    .collect();
                            }
                            if self.raw_iv.len() > 16 {
                                self.raw_iv.truncate(16);
                            }
                        }
                    });
                }
            });

            ui.label("");
            ui.label(format!("Number of CPU cores - {}", num_cpus::get_physical()));
            ui.label("");

            // if i add multithreads, uncomment
            if self.mode == Mode::ECB {
                ui.label("Select a number of threads to be used");
                ui.add(egui::Slider::new(
                    &mut self.num_threads,
                    1..=num_cpus::get() - 1,
                ));
            } else {
                self.num_threads = 1;
            }

            ui.label("\n");
            if supports_aes_ni() {
                ui.label("What implementation to use?");
                egui::ComboBox::from_label(format!(""))
                    .selected_text(format!("{:?}", self.implmentation))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.implmentation,
                            Implementation::Software,
                            "Software",
                        );
                        ui.selectable_value(
                            &mut self.implmentation,
                            Implementation::Hardware,
                            "Hardware",
                        )
                    });
            }

            ui.label("\n");
            if self.mode == Mode::ECB {
                ui.checkbox(&mut self.asnc, "Asynchronous mode");
                ui.label("\n");
            } else {
                self.asnc = false;
            }

            ui.horizontal(|ui| {
                let keys_are_empty = (self.raw_keys.key128.is_empty() && self.algorithm == Algorithm::AES_128 || self.raw_keys.key192.is_empty() && self.algorithm == Algorithm::AES_192 || self.raw_keys.key256.is_empty() && self.algorithm == Algorithm::AES_256)
                    || (!check_len(&self.raw_keys.key128, self.algorithm) && self.algorithm == Algorithm::AES_128 || !check_len(&self.raw_keys.key192, self.algorithm) && self.algorithm == Algorithm::AES_192 || !check_len(&self.raw_keys.key256, self.algorithm) && self.algorithm == Algorithm::AES_256)
                    || (self.mode == Mode::CBC
                        && (self.raw_iv.is_empty() || self.raw_iv.len() != 16));

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
                
                let pos = egui::AboveOrBelow::Below;

                if start_button.clicked() || ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::S)) && self.processing == false {
                    
                    self.processing = true;
                    match self.algorithm {
                        Algorithm::AES_128 => self.keys.key128 =  parse_128_key(&self.raw_keys.key128).unwrap(),
                        Algorithm::AES_192 => self.keys.key192 =  parse_192_key(&self.raw_keys.key192).unwrap(),
                        Algorithm::AES_256 => self.keys.key256 =  parse_256_key(&self.raw_keys.key256).unwrap(),
                    }

                    if keys_valid {
                        if self.mode == Mode::CBC {
                            self.iv = parse_iv(&self.raw_iv).unwrap().try_into().unwrap();
                        }

                        send(
                            self.input_file.clone(),
                            self.output_file.clone(),
                            self.algorithm.clone(),
                            self.action.clone(),
                            self.mode.clone(),
                            self.keys.clone(),
                            self.iv.clone(),
                            self.num_threads.clone(),
                            self.asnc.clone(),
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
    mode: Mode,
    keys: KeysArr,
    iv: [u8; 16],
    num_threads: usize,
    asnc: bool,
    tx: Sender<Duration>,
    ctx: egui::Context,
) {
    if asnc {
        tokio::spawn(async move {
            let res = process_async(
                input_file,
                output_file,
                algorithm,
                action,
                mode,
                keys,
                iv,
            )
            .await;
            if let Err(e) = tx.send(res) {
                eprintln!("Error sending result through channel: {}", e);
            }

            ctx.request_repaint();
        });
    } else {
        tokio::task::spawn_blocking(move || {
            let res = process(
                input_file,
                output_file,
                algorithm,
                action,
                mode,
                keys,
                iv,
                num_threads,
            );
             
            if let Err(e) = tx.send(res) {
                panic!("Error sending result through channel: {}", e);
            };

            ctx.request_repaint();
        });
    }
}

fn process(
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    action: Action,
    mode: Mode,
    keys: KeysArr,
    iv: [u8; 16],
    num_threads: usize,
) -> Duration {
    let input_file = File::open(&input_file).expect("Error opening input file");
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, input_file);
    let mut buffer = vec![0; CHUNK_SIZE];

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
    let iv = Arc::new(iv);
    let tasks_count = Arc::new(AtomicUsize::new(0));
    let mut chunk_index = 0;

    while let Ok(size) = reader.read(&mut buffer) {
        if size == 0 {
            break;
        }

        let input_data = buffer[..size].to_vec();
        let chunk_keys = Arc::clone(&keys);
        let chunk_iv = Arc::clone(&iv);
        let output = Arc::clone(&output_file);
        let task_count = Arc::clone(&tasks_count);
        let current_index = chunk_index;

        // Padding size and padded flag
        let (padding_size, padded) = if action == Action::Encrypt {
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
                    Algorithm::AES_128 => aes_128(mode, action, padded_data, chunk_keys.key128, *chunk_iv.clone(), None),
                    Algorithm::AES_192 => aes_192(mode, action, padded_data, chunk_keys.key192, *chunk_iv.clone(), None),
                    Algorithm::AES_256 => aes_256(mode, action, padded_data, chunk_keys.key256, *chunk_iv.clone(), None),
                };
            } else {
                chunk_result = match algorithm {
                    Algorithm::AES_128 => aes_128(mode, action, input_data.clone(), chunk_keys.key128, *chunk_iv.clone(), None),
                    Algorithm::AES_192 => aes_192(mode, action, input_data.clone(), chunk_keys.key192, *chunk_iv.clone(), None),
                    Algorithm::AES_256 => aes_256(mode, action, input_data.clone(), chunk_keys.key256, *chunk_iv.clone(), None),
                };

                if padded {
                    let padding_size = *chunk_result.0.last().unwrap_or(&0) as usize;
                    chunk_result.0.truncate(chunk_result.0.len() - padding_size);
                }
            }

            // Write the result to the output file
            let mut file = output.lock().unwrap();
            file.seek(SeekFrom::Start((current_index * CHUNK_SIZE) as u64))
                .expect("Failed to seek in output file");
            file.write_all(&chunk_result.0).expect("Failed to write to output file");

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

/* fn process(
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    action: Action,
    mode: Mode,
    keys: KeysArr,
    iv: [u8; 16],
    num_threads: usize,
) -> Duration {
    let file = std::fs::File::open(input_file).expect("Error opening a file :(");
    let mut reader = std::io::BufReader::with_capacity(CHUNK_SIZE, file);
    let mut buffer = vec![0; CHUNK_SIZE];
    let mut prev_block: Option<Vec<u8>> = None;
    let mut padded = false;
    let mut input_data: Vec<u8>;
    let padding_size: usize = 0;
    let mut num_padded = 0;
    let key128: [u8; 16] = keys.key128;
    let key192: [u8; 24] = keys.key192;
    let key256: [u8; 32] = keys.key256;

    let mut chunk_result: Vec<u8>;

    let mut file = std::fs::File::create(&output_file).unwrap();

    let start_time = Instant::now(); // Record the start time.

    while let Ok(size) = reader.read(&mut buffer) {
        if size == 0 {
            break;
        }
        if action == Action::Encrypt {
            let block_size = 16; // AES block size
            let padding_size = block_size - (size % block_size);
            input_data = if padding_size != block_size {
                padded = true;
                let mut padded_buffer = buffer[..size].to_vec();
                padded_buffer.extend(vec![padding_size as u8; padding_size]); // Add PKCS#7 padding
                padded_buffer
            } else {
                buffer[..size].to_vec()
            };
        } else {
            input_data = buffer[..size].to_vec();
        }
        if action == Action::Decrypt {
            num_padded = input_data[input_data.len() - 1];
        } 
        (chunk_result, prev_block) = match algorithm {
            Algorithm::AES_128 => aes_128(mode, action, input_data, key128, iv, prev_block),
            Algorithm::AES_192 => aes_192(mode, action, input_data, key192, iv, prev_block),
            Algorithm::AES_256 => aes_256(mode, action, input_data, key256, iv, prev_block),
        };
        if action == Action::Decrypt && size % 8 == 1 {
            let _ = chunk_result.pop();
            chunk_result.truncate(size - (num_padded as usize + 1));
        }
        if padded {
            chunk_result.push(padding_size as u8);
        }
        if let Err(e) = file.write_all(&chunk_result) {
            eprintln!("Uh-oh, problem with writing!: {e}");
        };

    }

    let crypt_time = start_time.elapsed();

    crypt_time
} */

async fn process_async(
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    action: Action,
    mode: Mode,
    keys: KeysArr,
    iv: [u8; 16],
) -> Duration {
    let file = tokio::fs::File::open(&input_file.as_str())
        .await
        .expect("Error opening a file :(");
    let mut reader = tokio::io::BufReader::with_capacity(CHUNK_SIZE, file);
    let mut buffer = vec![0; CHUNK_SIZE];
    let mut padded = false;
    let mut input_data: Vec<u8>;
    let mut padding_size: usize = 0;
    let mut num_padded = 0;
    let mut chunk_result = Vec::new();
    let key128 = keys.key128;
    let key192 = keys.key192;
    let key256 = keys.key256;
    let mut prev_block: Option<Vec<u8>> = None;

    let mut file = tokio::fs::File::create(&output_file).await.unwrap();

    let start_time = Instant::now(); // Record the start time.

    while let Ok(size) = reader.read(&mut buffer).await {
        if size == 0 {
            break;
        }
        if action == Action::Encrypt {
            padding_size = 8 - (size % 8);
            if padding_size != 8 {
                padded = true;
                buffer.extend(vec![0; padding_size]);
                input_data = buffer[..size + padding_size].to_vec();
            } else {
                input_data = buffer[..size].to_vec();
            };
        } else {
            input_data = buffer[..size].to_vec();
        }
        if action == Action::Decrypt {
            num_padded = input_data[input_data.len() - 1];
        }
        (chunk_result, prev_block) = match algorithm {
            Algorithm::AES_128 => aes_128(mode, action, input_data, key128, iv, prev_block),
            Algorithm::AES_192 => aes_192(mode, action, input_data, key192, iv, prev_block),
            Algorithm::AES_256 => aes_256(mode, action, input_data, key256, iv, prev_block),
            _ => unreachable!(),
        };
        
                if action == Action::Decrypt && size % 8 != 0 {
            let _ = chunk_result.pop();
            chunk_result.truncate(size - (num_padded as usize + 1));
        }
        if padded {
            chunk_result.push(padding_size as u8);
        }
        if let Err(e) = file.write_all(&chunk_result).await {
            eprintln!("Uh-oh, big problemo!: {e}");
        };
    }

    let crypt_time = start_time.elapsed();

    crypt_time
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


/// Collects an iv_str String variable and returns a 16-digit hex Key.
///
/// # Arguments
///
/// * `iv_str` - The IV as a 16-character hexadecimal string.
///
/// # Returns
///
/// A `Result` containing an array of u8s (IV) if successful, otherwise an error message.
fn parse_iv(iv_str: &str) -> Result<Vec<u8>, &'static str> {
    if iv_str.len() == 16 {
        let mut iv = Vec::with_capacity(16);
        for chunk in iv_str.as_bytes().chunks(2) {
            let byte =
                u8::from_str_radix(std::str::from_utf8(chunk).map_err(|_| "Invalid UTF-8")?, 16)
                    .map_err(|_| "Invalid hex format")?;
            iv.push(byte);
        }
        Ok(iv)
    } else {
        Err("IV must be a 16-character hexadecimal string.")
    }
}

/// Converts a u64 variable into an array of 8 u8s.
///
/// # Arguments
///
/// * `input` - The u64 variable to be converted.
///
/// # Returns
///
/// An array of 8 u8s representing the converted u64 variable.
fn u64_to_u8_array(input: u64) -> [u8; 8] {
    let mut result = [0u8; 8];

    for i in 0..8 {
        result[i] = ((input >> (i * 8)) & 0xFF) as u8;
    }

    result
}

#[inline(always)]
fn aes_128(mode: Mode, action: Action, input: Vec<u8>, key: [u8; 16], iv: [u8; 16], prev_block: Option<Vec<u8>>) -> (Vec<u8>, Option<Vec<u8>>) {
    let (result, next) = match (mode, action) {
        (Mode::ECB, Action::Encrypt) => aes_128_encrypt(&input, key),
        (Mode::ECB, Action::Decrypt) => aes_128_decrypt(&input, key),
        (Mode::CBC, Action::Encrypt) => unimplemented!(), 
        (Mode::CBC, Action::Decrypt) => unimplemented!(),
    };
    (result, next)  
}

fn aes_192(mode: Mode, action: Action, input: Vec<u8>, key: [u8; 24], iv: [u8; 16], prev_block: Option<Vec<u8>>) -> (Vec<u8>, Option<Vec<u8>>) {
    let (result, next) = match (mode, action) {
        (Mode::ECB, Action::Encrypt) => aes_192_encrypt(&input, key),
        (Mode::ECB, Action::Decrypt) => aes_192_decrypt(&input, key),
        (Mode::CBC, Action::Encrypt) => unimplemented!(),
        (Mode::CBC, Action::Decrypt) => unimplemented!(),
    };
    (result, next)  
}

fn aes_256(mode: Mode, action: Action, input: Vec<u8>, key: [u8; 32], iv: [u8; 16], prev_block: Option<Vec<u8>>) -> (Vec<u8>, Option<Vec<u8>>) {
    let (result, next) = match (mode, action) {
        (Mode::ECB, Action::Encrypt) => aes_256_encrypt(&input, key),
        (Mode::ECB, Action::Decrypt) => aes_256_decrypt(&input, key),
        (Mode::CBC, Action::Encrypt) => unimplemented!(),
        (Mode::CBC, Action::Decrypt) => unimplemented!(),
    };
    (result, next)  
}



/// Reads a line from standard input, trims it, and ensures it is a valid
/// 16-digit hex number.
///
/// # Arguments
///
/// * `input` - The input recieved from the user.
///
/// # Returns
///
/// Returns a true if input is valid 16-digit hex, false - otherwise.
fn check_hex_input(input: &String) -> bool {
    let hex_pattern = Regex::new(r"^[0-9A-Fa-f]{1,16}$").expect("Couldn't generate regex!");

    hex_pattern.is_match(&input.trim())
}

fn check_hex_input_128(input: &String) -> bool {
    let hex_pattern = Regex::new(r"^[0-9A-Fa-f]{1,16}$").expect("Couldn't generate regex!");

    hex_pattern.is_match(&input.trim())
}

fn check_hex_input_192(input: &String) -> bool {
    let hex_pattern = Regex::new(r"^[0-9A-Fa-f]{1,24}$").expect("Couldn't generate regex!");

    hex_pattern.is_match(&input.trim())
}

fn check_hex_input_256(input: &String) -> bool {
    let hex_pattern = Regex::new(r"^[0-9A-Fa-f]{1,32}$").expect("Couldn't generate regex!");

    hex_pattern.is_match(&input.trim())
}

fn check_len(input: &String, algorithm: Algorithm) -> bool {
    match algorithm {
        Algorithm::AES_128 => {
            if input.len() < 32 {
                false
            } else {
                true
            }
        }
        Algorithm::AES_192 => {
            if input.len() < 48 {
                false
            } else {
                true
            }
        }
        Algorithm::AES_256 => {
            if input.len() < 64 {
                false
            } else {
                true
            }
        }
    }
}

fn supports_aes_ni() -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    {
        if is_x86_feature_detected!("aes") {
            return true;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if is_aarch64_feature_detected!("aes") {
            return true;
        }
    }

    false
}

fn u64_from_bytes(bytes: &[u8]) -> u64 {
    if bytes.len() != 8 {
        panic!("Масив байтів повинен містити точно 8 байтів для конвертації в u64");
    }

    let mut result: u64 = 0;
    for i in 0..8 {
        result |= (bytes[i] as u64) << (56 - 8 * i);
    }

    result
}
