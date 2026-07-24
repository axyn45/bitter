use crate::api::{ApiClient, CipherSync, FolderSync};
use crate::config::{Config, Session};
use crate::storage::VaultRepository;
use crate::{crypto, storage};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use std::io;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
enum AppState {
    Login,
    Lock,
    Dashboard,
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ActivePanel {
    Left,   // Categories / Folders
    Middle, // Cipher List
    Right,  // Cipher Details
    Search, // Search Input
}

struct App<'a> {
    config: &'a mut Config,
    repo: &'a mut VaultRepository,
    state: AppState,
    active_panel: ActivePanel,
    
    // Auth inputs
    email_input: String,
    password_input: String,
    server_input: String,
    
    // Auth focus (0: Email, 1: Password, 2: Server)
    auth_focus: usize,
    
    // Decryption keys held in memory while TUI is running
    keys: Option<([u8; 32], [u8; 32])>,
    user_id: Option<String>,
    
    // Vault data cached in memory
    categories: Vec<&'static str>,
    folders: Vec<FolderSync>,
    ciphers: Vec<CipherSync>,
    decrypted_keys: Vec<storage::SshKeyItem>,
    
    // Filtering and selection states
    search_query: String,
    left_selected_folder: Option<usize>, // None means a Category is selected
    left_list_state: ListState,
    middle_list_state: ListState,
    
    // UI details
    mask_secrets: bool,
    status_message: Option<(String, Instant)>,
}

impl<'a> App<'a> {
    fn new(config: &'a mut Config, repo: &'a mut VaultRepository) -> Self {
        let server_input = config.server_url.clone();
        let mut app = Self {
            config,
            repo,
            state: AppState::Lock,
            active_panel: ActivePanel::Left,
            email_input: String::new(),
            password_input: String::new(),
            server_input,
            auth_focus: 0,
            keys: None,
            user_id: None,
            categories: vec![
                "All Items",
                "Favorites",
                "Logins",
                "Cards",
                "Identities",
                "Secure Notes",
            ],
            folders: Vec::new(),
            ciphers: Vec::new(),
            decrypted_keys: Vec::new(),
            search_query: String::new(),
            left_selected_folder: None,
            left_list_state: ListState::default(),
            middle_list_state: ListState::default(),
            mask_secrets: true,
            status_message: None,
        };
        
        app.left_list_state.select(Some(0));
        app
    }

    fn set_status(&mut self, msg: &str) {
        self.status_message = Some((msg.to_string(), Instant::now()));
    }

    fn check_status_expiry(&mut self) {
        if let Some((_, time)) = &self.status_message {
            if time.elapsed() > Duration::from_secs(4) {
                self.status_message = None;
            }
        }
    }

    fn try_load_saved_keys(&mut self) -> Result<bool, String> {
        if let Some(keys) = self.repo.load_saved_keys()? {
            self.keys = Some(keys);
            if let Some(session) = self.repo.load_session()? {
                self.user_id = Some(session.user_id);
                self.state = AppState::Dashboard;
                self.load_vault_data()?;
                return Ok(true);
            }
        }
        
        // If not unlocked, check if logged in
        if let Some(session) = self.repo.load_session()? {
            self.email_input = session.email;
            self.user_id = Some(session.user_id);
            self.state = AppState::Lock;
        } else {
            self.state = AppState::Login;
        }
        Ok(false)
    }

    fn load_vault_data(&mut self) -> Result<(), String> {
        let (enc_key, mac_key) = match &self.keys {
            Some(k) => k,
            None => return Ok(()),
        };
        let user_id = match &self.user_id {
            Some(uid) => uid,
            None => return Ok(()),
        };
        
        self.folders = self.repo.list_folders(user_id)?;
        self.ciphers = self.repo.list_ciphers(user_id)?;
        
        // Decrypt SSH keys to memory
        if let Ok(keys) = storage::decrypt_ssh_keys_from_db(self.repo, Some(user_id), enc_key, mac_key) {
            self.decrypted_keys = keys;
        }
        
        Ok(())
    }

    async fn handle_tui_login(&mut self) -> Result<(), String> {
        if self.email_input.trim().is_empty() || self.password_input.trim().is_empty() {
            return Err("Email and Password cannot be empty".to_string());
        }

        let api_client = ApiClient::new(&self.server_input);
        self.set_status("Contacting Bitwarden server...");

        // 1. Fetch prelogin (KDF parameters)
        let prelogin = api_client
            .prelogin(&self.email_input)
            .await
            .map_err(|e| format!("KDF prelogin failed: {}", e))?;

        // 2. Derive master key locally
        let master_key = crypto::prompt_and_derive_master_key(
            Some(self.password_input.clone()),
            &self.email_input,
            prelogin.kdf,
            prelogin.kdf_iterations,
            prelogin.kdf_memory,
            prelogin.kdf_parallelism,
            None,
        )?;

        // 3. Login using master password hash
        let login_hash = crypto::derive_login_hash(&master_key, &self.password_input);
        let device_id = crate::config::generate_device_id();
        
        let token_resp = api_client
            .login_password(&self.email_input, &login_hash, &device_id, "bitter_tui")
            .await
            .map_err(|e| format!("Login failed: {}", e))?;

        // 4. Decrypt symmetric keys
        let (enc_key, mac_key) = crypto::decrypt_symmetric_key(&master_key, &token_resp.key)
            .map_err(|e| format!("Failed to decrypt symmetric keys: {}", e))?;

        // 5. Initialize session
        let existing_session = self.repo.load_session().unwrap_or(None);
        let (timeout, timeout_action) = if let Some(ref s) = existing_session {
            (s.timeout.clone(), s.timeout_action)
        } else {
            (crate::config::DEFAULT_TIMEOUT.to_string(), crate::config::TimeoutAction::Lock)
        };
        let mut session = Session {
            user_id: "".to_string(), // populated in perform_sync
            email: self.email_input.clone(),
            device_id,
            access_token: Some(token_resp.access_token.clone()),
            refresh_token: token_resp.refresh_token.clone(),
            last_sync_time: None,
            server_url: self.server_input.clone(),
            timeout,
            timeout_action,
        };

        self.set_status("Syncing vault data...");
        // 6. Perform silent sync
        crate::commands::perform_sync(&api_client, &token_resp.access_token, &mut session, true).await?;

        // 7. Save keys locally & notify agent daemon silently
        crate::commands::unlock_with_keys(self.repo, &session, &enc_key, &mac_key, true).await?;

        // Cache parameters
        self.keys = Some((enc_key, mac_key));
        self.user_id = Some(session.user_id);
        self.config.server_url = self.server_input.clone();
        let _ = self.config.save();

        self.password_input.clear();
        self.state = AppState::Dashboard;
        self.load_vault_data()?;
        self.set_status("Logged in and synced successfully!");

        Ok(())
    }

    async fn handle_tui_unlock(&mut self) -> Result<(), String> {
        if self.password_input.trim().is_empty() {
            return Err("Password cannot be empty".to_string());
        }

        let session = self.repo.load_session()?
            .ok_or_else(|| "No session found. Please log in first.".to_string())?;

        let api_client = ApiClient::new(&session.server_url);
        self.set_status("Deriving keys and verifying...");

        // Try to fetch KDF options from server, fallback to local cache
        let (enc_key, mac_key) = match api_client.prelogin(&session.email).await {
            Ok(prelogin) => {
                let master_key = crypto::prompt_and_derive_master_key(
                    Some(self.password_input.clone()),
                    &session.email,
                    prelogin.kdf,
                    prelogin.kdf_iterations,
                    prelogin.kdf_memory,
                    prelogin.kdf_parallelism,
                    None,
                )?;
                
                // Fetch token
                let login_hash = crypto::derive_login_hash(&master_key, &self.password_input);
                let token_resp = api_client
                    .login_password(&session.email, &login_hash, &session.device_id, "bitter_tui")
                    .await
                    .map_err(|e| format!("Password verification failed: {}", e))?;
                
                crypto::decrypt_symmetric_key(&master_key, &token_resp.key)?
            }
            Err(_) => {
                // Offline fallback
                let sync_resp = self.repo.load_sync_response()?;
                let (_, enc, mac) = storage::decrypt_sync_response_offline(&sync_resp, &self.password_input)?;
                (enc, mac)
            }
        };

        // Notify running daemon silently
        crate::commands::unlock_with_keys(self.repo, &session, &enc_key, &mac_key, true).await?;

        self.keys = Some((enc_key, mac_key));
        self.password_input.clear();
        self.state = AppState::Dashboard;
        self.load_vault_data()?;
        self.set_status("Vault unlocked successfully!");

        Ok(())
    }

    fn handle_tui_logout(&mut self) {
        self.keys = None;
        self.user_id = None;
        self.ciphers.clear();
        self.folders.clear();
        self.decrypted_keys.clear();
        self.email_input.clear();
        self.password_input.clear();
        
        let _ = self.repo.logout_active_user();
        
        self.state = AppState::Login;
        self.active_panel = ActivePanel::Left;
        self.set_status("Logged out successfully.");
    }

    fn get_filtered_ciphers(&self) -> Vec<&CipherSync> {
        let left_idx = self.left_list_state.selected().unwrap_or(0);
        let total_categories = self.categories.len();

        let matches_filter = |c: &CipherSync| -> bool {
            // Category filter
            if left_idx < total_categories {
                match self.categories[left_idx] {
                    "All Items" => true,
                    "Favorites" => c.favorite,
                    "Logins" => c.r#type == 1,
                    "Cards" => c.r#type == 3,
                    "Identities" => c.r#type == 4,
                    "Secure Notes" => c.r#type == 2,
                    _ => true,
                }
            } else {
                // Folder filter
                let folder_idx = left_idx - total_categories;
                if folder_idx < self.folders.len() {
                    let folder_id = &self.folders[folder_idx].id;
                    c.folder_id.as_ref() == Some(folder_id)
                } else {
                    true
                }
            }
        };

        self.ciphers
            .iter()
            .filter(|c| {
                if !matches_filter(c) {
                    return false;
                }
                if self.search_query.is_empty() {
                    return true;
                }
                let query = self.search_query.to_lowercase();
                c.name.as_ref().map(|n| n.to_lowercase().contains(&query)).unwrap_or(false)
                    || c.login.as_ref().and_then(|l| l.username.as_ref()).map(|u| u.to_lowercase().contains(&query)).unwrap_or(false)
            })
            .collect()
    }
}

pub async fn run(config: &mut Config, repo: &mut VaultRepository) -> Result<(), String> {
    enable_raw_mode().map_err(|e| e.to_string())?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).map_err(|e| e.to_string())?;
    
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| e.to_string())?;

    let mut app = App::new(config, repo);
    let _ = app.try_load_saved_keys();

    let res = run_loop(&mut terminal, &mut app).await;

    disable_raw_mode().map_err(|e| e.to_string())?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(|e| e.to_string())?;
    terminal.show_cursor().map_err(|e| e.to_string())?;

    res
}

async fn run_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App<'_>,
) -> Result<(), String> {
    loop {
        app.check_status_expiry();
        
        terminal
            .draw(|f| ui_draw(f, app))
            .map_err(|e| e.to_string())?;

        if event::poll(Duration::from_millis(100)).map_err(|e| e.to_string())? {
            if let Event::Key(key) = event::read().map_err(|e| e.to_string())? {
                if key.kind == event::KeyEventKind::Press {
                    if handle_key_input(key, app).await? {
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn handle_key_input(key: KeyEvent, app: &mut App<'_>) -> Result<bool, String> {
    // Global quits
    if key.code == KeyCode::Char('q') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Ok(true);
    }

    match &app.state {
        AppState::Login => handle_login_keys(key, app).await,
        AppState::Lock => handle_lock_keys(key, app).await,
        AppState::Dashboard => handle_dashboard_keys(key, app).await,
        AppState::Error(_err) => {
            // Dismiss error on any key except escape/quit
            if key.code == KeyCode::Esc || key.code == KeyCode::Char('q') {
                return Ok(true);
            }
            app.state = AppState::Dashboard;
            Ok(false)
        }
    }
}

async fn handle_login_keys(key: KeyEvent, app: &mut App<'_>) -> Result<bool, String> {
    match key.code {
        KeyCode::Esc => return Ok(true),
        KeyCode::Tab => {
            app.auth_focus = (app.auth_focus + 1) % 3;
        }
        KeyCode::BackTab => {
            app.auth_focus = (app.auth_focus + 2) % 3;
        }
        KeyCode::Enter => {
            if app.auth_focus == 2 || key.modifiers.contains(KeyModifiers::CONTROL) {
                if let Err(e) = app.handle_tui_login().await {
                    app.state = AppState::Error(e);
                }
            } else {
                app.auth_focus = (app.auth_focus + 1) % 3;
            }
        }
        KeyCode::Char(c) => {
            match app.auth_focus {
                0 => app.email_input.push(c),
                1 => app.password_input.push(c),
                2 => app.server_input.push(c),
                _ => {}
            }
        }
        KeyCode::Backspace => {
            match app.auth_focus {
                0 => { app.email_input.pop(); }
                1 => { app.password_input.pop(); }
                2 => { app.server_input.pop(); }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(false)
}

async fn handle_lock_keys(key: KeyEvent, app: &mut App<'_>) -> Result<bool, String> {
    match key.code {
        KeyCode::Esc => {
            // Logout instead of quitting if they want to escape lock screen
            app.handle_tui_logout();
        }
        KeyCode::Enter => {
            if let Err(e) = app.handle_tui_unlock().await {
                app.state = AppState::Error(e);
            }
        }
        KeyCode::Char(c) => {
            app.password_input.push(c);
        }
        KeyCode::Backspace => {
            app.password_input.pop();
        }
        _ => {}
    }
    Ok(false)
}

async fn handle_dashboard_keys(key: KeyEvent, app: &mut App<'_>) -> Result<bool, String> {
    // Focus specific key shortcuts
    if app.active_panel == ActivePanel::Search {
        match key.code {
            KeyCode::Esc => {
                app.active_panel = ActivePanel::Middle;
            }
            KeyCode::Enter => {
                app.active_panel = ActivePanel::Middle;
            }
            KeyCode::Char(c) => {
                app.search_query.push(c);
                app.middle_list_state.select(Some(0));
            }
            KeyCode::Backspace => {
                app.search_query.pop();
                app.middle_list_state.select(Some(0));
            }
            _ => {}
        }
        return Ok(false);
    }

    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => return Ok(true),
        
        // Navigation between panes
        KeyCode::Tab => {
            app.active_panel = match app.active_panel {
                ActivePanel::Left => ActivePanel::Middle,
                ActivePanel::Middle => ActivePanel::Right,
                ActivePanel::Right => ActivePanel::Left,
                ActivePanel::Search => ActivePanel::Middle,
            };
        }
        KeyCode::BackTab => {
            app.active_panel = match app.active_panel {
                ActivePanel::Left => ActivePanel::Right,
                ActivePanel::Middle => ActivePanel::Left,
                ActivePanel::Right => ActivePanel::Middle,
                ActivePanel::Search => ActivePanel::Left,
            };
        }
        
        // Global Actions
        KeyCode::Char('/') => {
            app.active_panel = ActivePanel::Search;
        }
        KeyCode::Char('s') => {
            app.set_status("Syncing with Bitwarden server...");
            if let Some(mut session) = app.repo.load_session().unwrap_or(None) {
                let api_client = ApiClient::new(&session.server_url);
                if let Some(token) = session.access_token.clone() {
                    match crate::commands::perform_sync(&api_client, &token, &mut session, true).await {
                        Ok(_) => {
                            let _ = app.load_vault_data();
                            app.set_status("Sync completed successfully.");
                        }
                        Err(e) => app.state = AppState::Error(format!("Sync failed: {}", e)),
                    }
                }
            }
        }
        KeyCode::Char('o') => {
            app.mask_secrets = !app.mask_secrets;
        }
        KeyCode::Char('l') => {
            app.keys = None;
            app.state = AppState::Lock;
            app.set_status("Vault locked.");
        }
        KeyCode::Char('L') => {
            app.handle_tui_logout();
        }
        
        // Arrows / Navigation keys inside focused panes
        KeyCode::Up | KeyCode::Char('k') => {
            match app.active_panel {
                ActivePanel::Left => {
                    let curr = app.left_list_state.selected().unwrap_or(0);
                    if curr > 0 {
                        app.left_list_state.select(Some(curr - 1));
                        app.middle_list_state.select(Some(0));
                    }
                }
                ActivePanel::Middle => {
                    let curr = app.middle_list_state.selected().unwrap_or(0);
                    if curr > 0 {
                        app.middle_list_state.select(Some(curr - 1));
                    }
                }
                _ => {}
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            match app.active_panel {
                ActivePanel::Left => {
                    let curr = app.left_list_state.selected().unwrap_or(0);
                    let max = app.categories.len() + app.folders.len();
                    if curr + 1 < max {
                        app.left_list_state.select(Some(curr + 1));
                        app.middle_list_state.select(Some(0));
                    }
                }
                ActivePanel::Middle => {
                    let curr = app.middle_list_state.selected().unwrap_or(0);
                    let len = app.get_filtered_ciphers().len();
                    if len > 0 && curr + 1 < len {
                        app.middle_list_state.select(Some(curr + 1));
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(false)
}

fn ui_draw(f: &mut ratatui::Frame, app: &mut App<'_>) {
    match &app.state {
        AppState::Login => draw_login(f, app),
        AppState::Lock => draw_lock(f, app),
        AppState::Dashboard => draw_dashboard(f, app),
        AppState::Error(err) => draw_error(f, err),
    }
}

fn draw_login(f: &mut ratatui::Frame, app: &App<'_>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(f.area());

    // Title
    let title_block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Magenta));
    let title = Paragraph::new(" bitter : Bitwarden Client - Login ")
        .alignment(ratatui::layout::Alignment::Center)
        .block(title_block);
    f.render_widget(title, chunks[0]);

    // Form Box
    let form_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Email
            Constraint::Length(3), // Password
            Constraint::Length(3), // Server URL
            Constraint::Min(1),    // Action Hint
        ])
        .split(chunks[1]);

    let get_style = |idx| {
        if app.auth_focus == idx {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        }
    };

    // Email Input
    let email_widget = Paragraph::new(app.email_input.as_str())
        .block(Block::default().borders(Borders::ALL).title(" Email Address ").style(get_style(0)));
    f.render_widget(email_widget, form_chunks[0]);

    // Password Input (Masked)
    let masked_password: String = "*".repeat(app.password_input.len());
    let password_widget = Paragraph::new(masked_password.as_str())
        .block(Block::default().borders(Borders::ALL).title(" Master Password ").style(get_style(1)));
    f.render_widget(password_widget, form_chunks[1]);

    // Server URL
    let server_widget = Paragraph::new(app.server_input.as_str())
        .block(Block::default().borders(Borders::ALL).title(" Bitwarden Server URL ").style(get_style(2)));
    f.render_widget(server_widget, form_chunks[2]);

    // Hints
    let hint_widget = Paragraph::new("Press [Tab] to switch inputs. Press [Enter] to submit credentials. Press [Esc] to exit.")
        .alignment(ratatui::layout::Alignment::Center)
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hint_widget, form_chunks[3]);

    // Status bar
    draw_status_bar(f, chunks[2], app);
}

fn draw_lock(f: &mut ratatui::Frame, app: &App<'_>) {
    let size = f.area();
    let lock_area = Rect::new(
        size.x + (size.width.saturating_sub(60)) / 2,
        size.y + (size.height.saturating_sub(10)) / 2,
        60.min(size.width),
        10.min(size.height),
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Vault Locked ")
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
    f.render_widget(block, lock_area);

    let inner_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(lock_area.inner(ratatui::layout::Margin { horizontal: 2, vertical: 1 }));

    let email_text = format!("Email: {}", app.email_input);
    f.render_widget(Paragraph::new(email_text.as_str()), inner_layout[0]);
    f.render_widget(Paragraph::new("Your local vault cache is locked."), inner_layout[1]);

    // Password input
    let masked_password: String = "*".repeat(app.password_input.len());
    let pass_block = Block::default()
        .borders(Borders::ALL)
        .title(" Enter Master Password ")
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(Paragraph::new(masked_password.as_str()).block(pass_block), inner_layout[2]);

    f.render_widget(
        Paragraph::new("Press [Enter] to unlock. Press [Esc] to Logout / Wipe Cache.")
            .alignment(ratatui::layout::Alignment::Center)
            .style(Style::default().fg(Color::DarkGray)),
        inner_layout[3],
    );
}

fn draw_error(f: &mut ratatui::Frame, err: &str) {
    let size = f.area();
    let area = Rect::new(
        size.x + (size.width.saturating_sub(50)) / 2,
        size.y + (size.height.saturating_sub(8)) / 2,
        50.min(size.width),
        8.min(size.height),
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Error ")
        .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));
    f.render_widget(block, area);

    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(2)])
        .split(area.inner(ratatui::layout::Margin { horizontal: 2, vertical: 1 }));

    f.render_widget(
        Paragraph::new(err).wrap(Wrap { trim: true }).style(Style::default().fg(Color::LightRed)),
        inner[0],
    );

    f.render_widget(
        Paragraph::new("Press any key to dismiss.")
            .alignment(ratatui::layout::Alignment::Center)
            .style(Style::default().fg(Color::DarkGray)),
        inner[1],
    );
}

fn draw_dashboard(f: &mut ratatui::Frame, app: &mut App<'_>) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Top header / search
            Constraint::Min(10),   // Main 3 panes
            Constraint::Length(3), // Footer status bar
        ])
        .split(f.area());

    // 1. Header (Email / Server / Search query)
    let header_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(main_chunks[0]);

    let user_info = format!(
        " User: {} | Server: {}",
        app.email_input,
        app.config.server_url
    );
    f.render_widget(
        Paragraph::new(user_info.as_str()).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Active Session ")
                .style(Style::default().fg(Color::DarkGray)),
        ),
        header_chunks[0],
    );

    let search_style = if app.active_panel == ActivePanel::Search {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    let search_widget = Paragraph::new(app.search_query.as_str()).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Search Vault [/] ")
            .style(search_style),
    );
    f.render_widget(search_widget, header_chunks[1]);

    // 2. Main 3-Pane split
    let pane_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25), // Navigation
            Constraint::Percentage(35), // Item List
            Constraint::Percentage(40), // Item details
        ])
        .split(main_chunks[1]);

    draw_left_panel(f, pane_chunks[0], app);
    draw_middle_panel(f, pane_chunks[1], app);
    draw_right_panel(f, pane_chunks[2], app);

    // 3. Footer
    draw_status_bar(f, main_chunks[2], app);
}

fn draw_left_panel(f: &mut ratatui::Frame, area: Rect, app: &mut App<'_>) {
    let border_style = if app.active_panel == ActivePanel::Left {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Categories & Folders ")
        .style(border_style);

    let mut items = Vec::new();
    
    // Render categories
    for cat in &app.categories {
        items.push(ListItem::new(Span::raw(format!("  ★  {}", cat))));
    }

    // Render folders
    items.push(ListItem::new(Span::styled("  -- Folders --", Style::default().fg(Color::DarkGray))));
    for folder in &app.folders {
        let name = decrypt_to_string(&folder.name, &app.keys);
        items.push(ListItem::new(Span::raw(format!("  📁  {}", name))));
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.left_list_state);
}

fn draw_middle_panel(f: &mut ratatui::Frame, area: Rect, app: &mut App<'_>) {
    let border_style = if app.active_panel == ActivePanel::Middle {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Vault Entries ")
        .style(border_style);

    let filtered = app.get_filtered_ciphers();
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|c| {
            let raw_name = c.name.as_deref().unwrap_or("[No Name]");
            let cipher_keys = decrypt_cipher_key(c, &app.keys);
            let name = decrypt_to_string(raw_name, &cipher_keys);
            let icon = match c.r#type {
                1 => "🔑", // Login
                2 => "📝", // Secure Note
                3 => "💳", // Card
                4 => "👤", // Identity
                5 | 100 => "🗝️", // SSH Key
                _ => "📦",
            };
            let mut line_spans = vec![Span::raw(format!("{} {}", icon, name))];
            if c.favorite {
                line_spans.push(Span::styled(" ★", Style::default().fg(Color::Yellow)));
            }
            ListItem::new(Line::from(line_spans))
        })
        .collect();

    let list = List::new(items)
        .block(block)
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    f.render_stateful_widget(list, area, &mut app.middle_list_state);
}

fn draw_right_panel(f: &mut ratatui::Frame, area: Rect, app: &App<'_>) {
    let border_style = if app.active_panel == ActivePanel::Right {
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Entry Details ")
        .style(border_style);

    let filtered = app.get_filtered_ciphers();
    let selected_idx = app.middle_list_state.selected().unwrap_or(0);

    if filtered.is_empty() || selected_idx >= filtered.len() {
        f.render_widget(
            Paragraph::new("Select an entry to view details.")
                .alignment(ratatui::layout::Alignment::Center)
                .block(block)
                .style(Style::default().fg(Color::DarkGray)),
            area,
        );
        return;
    }

    let c = filtered[selected_idx];
    let cipher_keys = decrypt_cipher_key(c, &app.keys);
    let mut details_lines = Vec::new();

    let add_field = |lines: &mut Vec<Line>, label: &str, val: Option<&str>, is_secret: bool| {
        if let Some(v) = val {
            lines.push(Line::from(vec![
                Span::styled(format!("{}: ", label), Style::default().fg(Color::DarkGray)),
                if is_secret && app.mask_secrets {
                    Span::styled("••••••••".to_string(), Style::default().fg(Color::Red))
                } else {
                    Span::raw(v.to_string())
                },
            ]));
        }
    };

    // Title / Header
    let decrypted_title = c.name.as_deref().map(|n| decrypt_to_string(n, &cipher_keys)).unwrap_or_else(|| "[No Name]".to_string());
    details_lines.push(Line::from(Span::styled(
        decrypted_title,
        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
    )));
    details_lines.push(Line::from(Span::styled(
        format!("Type: {}", match c.r#type {
            1 => "Login",
            2 => "Secure Note",
            3 => "Card",
            4 => "Identity",
            5 | 100 => "SSH Key",
            _ => "Unknown",
        }),
        Style::default().fg(Color::DarkGray),
    )));
    details_lines.push(Line::from(""));

    // Decrypt fields if keys are available
    if app.keys.is_some() {
        if c.r#type == 1 {
            // Login Item
            if let Some(login_sync) = &c.login {
                let decrypted_username = login_sync.username.as_ref().map(|u| {
                    decrypt_to_string(u, &cipher_keys)
                });
                let decrypted_password = login_sync.password.as_ref().map(|p| {
                    decrypt_to_string(p, &cipher_keys)
                });
                let decrypted_uri = login_sync.uri.as_ref().map(|u| {
                    decrypt_to_string(u, &cipher_keys)
                });

                add_field(&mut details_lines, "Username", decrypted_username.as_deref(), false);
                add_field(&mut details_lines, "Password", decrypted_password.as_deref(), true);
                add_field(&mut details_lines, "URI/Website", decrypted_uri.as_deref(), false);
            }
        }

        // Custom Fields
        if let Some(fields) = &c.fields {
            if !fields.is_empty() {
                details_lines.push(Line::from(""));
                details_lines.push(Line::from(Span::styled("Custom Fields:", Style::default().fg(Color::Yellow))));
                for f in fields {
                    let decrypted_val = f.value.as_ref().map(|v| {
                        decrypt_to_string(v, &cipher_keys)
                    });
                    let is_secret = f.r#type == 1; // Secret field type in Bitwarden
                    let decrypted_field_name = decrypt_to_string(&f.name, &cipher_keys);
                    add_field(&mut details_lines, &decrypted_field_name, decrypted_val.as_deref(), is_secret);
                }
            }
        }

        // Notes
        if let Some(notes) = &c.notes {
            let decrypted_notes = decrypt_to_string(notes, &cipher_keys);
            details_lines.push(Line::from(""));
            details_lines.push(Line::from(Span::styled("Notes:", Style::default().fg(Color::Yellow))));
            details_lines.push(Line::from(decrypted_notes));
        }

        // Native SSH Key details
        if let Some(ref ssh_key_sync) = c.ssh_key {
            details_lines.push(Line::from(""));
            details_lines.push(Line::from(Span::styled("SSH Key Details:", Style::default().fg(Color::Yellow))));
            if let Some(ref enc_priv) = ssh_key_sync.private_key {
                let decrypted_priv = decrypt_to_string(enc_priv, &cipher_keys);
                add_field(&mut details_lines, "Private Key", Some(&decrypted_priv), true);
            }
            if let Some(ref enc_pub) = ssh_key_sync.public_key {
                let decrypted_pub = decrypt_to_string(enc_pub, &cipher_keys);
                add_field(&mut details_lines, "Public Key", Some(&decrypted_pub), false);
            }
        }
        
        // Associated SSH Key (if extracted by agent module)
        if let Some(key_item) = app.decrypted_keys.iter().find(|k| k.id == c.id) {
            details_lines.push(Line::from(""));
            details_lines.push(Line::from(Span::styled("SSH Private Key Detected:", Style::default().fg(Color::Yellow))));
            add_field(&mut details_lines, "Private Key Type", Some("PEM / OpenSSH format"), false);
            add_field(&mut details_lines, "Private Key Payload", Some(&key_item.private_key), true);
        }
    } else {
        details_lines.push(Line::from(Span::styled("Locked (Master key missing)", Style::default().fg(Color::Red))));
    }

    let paragraph = Paragraph::new(details_lines)
        .block(block)
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

fn draw_status_bar(f: &mut ratatui::Frame, area: Rect, app: &App<'_>) {
    let block = Block::default()
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black));

    let shortcut_text = match &app.state {
        AppState::Dashboard => " [Tab] Switch Pane | [/] Search | [o] Toggle Mask | [s] Sync | [l] Lock | [L] Logout | [q] Quit ",
        AppState::Login => " [Tab] Next Input | [Enter] Submit | [Esc] Cancel / Exit ",
        AppState::Lock => " [Enter] Unlock Vault | [Esc] Logout & Wipe Cache ",
        _ => " bitter SSH Client ",
    };

    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area.inner(ratatui::layout::Margin { horizontal: 1, vertical: 1 }));

    // Left status message (errors / updates)
    let status_str = if let Some((msg, _)) = &app.status_message {
        msg.as_str()
    } else {
        "Ready"
    };
    let status_widget = Paragraph::new(status_str).style(Style::default().fg(Color::Green));

    // Right shortcut guides
    let shortcut_widget = Paragraph::new(shortcut_text)
        .alignment(ratatui::layout::Alignment::Right)
        .style(Style::default().fg(Color::DarkGray));

    f.render_widget(block, area);
    f.render_widget(status_widget, layout[0]);
    f.render_widget(shortcut_widget, layout[1]);
}

fn decrypt_to_string(cipher_text: &str, keys: &Option<([u8; 32], [u8; 32])>) -> String {
    let (enc, mac) = match keys {
        Some(k) => k,
        None => return cipher_text.to_string(),
    };
    match crypto::decrypt_cipher_string(cipher_text, enc, mac) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|_| cipher_text.to_string()),
        Err(_) => cipher_text.to_string(),
    }
}

fn decrypt_cipher_key(
    cipher: &CipherSync,
    keys: &Option<([u8; 32], [u8; 32])>,
) -> Option<([u8; 32], [u8; 32])> {
    let (user_enc, user_mac) = keys.as_ref()?;
    let (active_enc, active_mac) = (*user_enc, *user_mac);

    if let Some(ref cipher_key_str) = cipher.key {
        if let Ok(decrypted) = crypto::decrypt_cipher_string(cipher_key_str, &active_enc, &active_mac) {
            if decrypted.len() == 64 {
                let mut ck_enc = [0u8; 32];
                let mut ck_mac = [0u8; 32];
                ck_enc.copy_from_slice(&decrypted[0..32]);
                ck_mac.copy_from_slice(&decrypted[32..64]);
                return Some((ck_enc, ck_mac));
            }
        }
    }

    Some((active_enc, active_mac))
}
