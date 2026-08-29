//! Split-screen terminal UI, the way tt++ does it: a VT100 scroll region for
//! server output (the terminal handles wrapping and ANSI natively), a status
//! bar, and an input line at the bottom.
//!
//! Invariant: the DECSC-saved cursor (ESC 7) always holds the output
//! position inside the scroll region, including its live SGR state, so
//! server color that dangles across our redraws is preserved.
//!
//! Scrollback: completed lines are kept in a ring buffer (also used for
//! resize redraws). PageUp/PageDown browse it; while browsing, incoming
//! text keeps accumulating in the buffer and the view stays frozen.

use std::collections::VecDeque;
use std::io::{self, Stdout, Write};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal;

const SCROLLBACK_MAX: usize = 10_000;

pub enum InputResult {
    None,
    Submit(String),
    Tab,
    Quit,
}

pub struct SplitUi {
    out: Stdout,
    pub cols: u16,
    pub rows: u16,
    input: String,
    cursor: usize, // byte offset into input
    history: Vec<String>,
    hist_pos: Option<usize>,
    stash: String,
    pub masked: bool, // server ECHO: hide typed text
    pub repeat_char: char,
    status: String,
    /// completed output lines (raw, with ANSI)
    scrollback: VecDeque<String>,
    /// bytes of the current (unterminated) output line already on screen
    partial: String,
    /// lines scrolled up from the live end; 0 = live view
    view_offset: usize,
}

impl SplitUi {
    pub fn new() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let (cols, rows) = terminal::size().unwrap_or((80, 24));
        let mut ui = SplitUi {
            out: io::stdout(),
            cols: cols.max(10),
            rows: rows.max(4),
            input: String::new(),
            cursor: 0,
            history: Vec::new(),
            hist_pos: None,
            stash: String::new(),
            masked: false,
            repeat_char: '!',
            status: String::new(),
            scrollback: VecDeque::new(),
            partial: String::new(),
            view_offset: 0,
        };
        ui.layout()?;
        Ok(ui)
    }

    fn out_rows(&self) -> u16 {
        self.rows.saturating_sub(2).max(1)
    }

    /// Clear, set scroll region, park output cursor at the region's bottom
    /// so text scrolls upward like a normal terminal.
    fn layout(&mut self) -> io::Result<()> {
        write!(
            self.out,
            "\x1b[0m\x1b[2J\x1b[1;{}r\x1b[{};1H\x1b7",
            self.out_rows(),
            self.out_rows()
        )?;
        self.draw_status_bar()?;
        self.draw_input()?;
        self.out.flush()
    }

    pub fn set_status(&mut self, text: &str) -> io::Result<()> {
        self.status = text.to_string();
        self.draw_status_bar()?;
        self.draw_input()?;
        self.out.flush()
    }

    fn draw_status_bar(&mut self) -> io::Result<()> {
        let row = self.rows.saturating_sub(1).max(1);
        let width = self.cols as usize;
        let scroll = if self.view_offset > 0 {
            format!("[scrollback -{}, PgDn/Esc to return] ", self.view_offset)
        } else {
            String::new()
        };
        let text = format!("─ {} {}", self.status, scroll);
        let mut bar: String = text.chars().take(width).collect();
        while bar.chars().count() < width {
            bar.push('─');
        }
        write!(self.out, "\x1b[{};1H\x1b[0;2m{}\x1b[0m", row, bar)
    }

    /// Write raw output (expects \r\n line endings) into the scroll region.
    pub fn write_output(&mut self, raw: &str) -> io::Result<()> {
        if raw.is_empty() {
            return Ok(());
        }
        // bookkeeping for the ring buffer
        for piece in raw.split_inclusive('\n') {
            if let Some(stripped) = piece.strip_suffix('\n') {
                let line = stripped.strip_suffix('\r').unwrap_or(stripped);
                self.partial.push_str(line);
                let done = std::mem::take(&mut self.partial);
                self.scrollback.push_back(done);
                if self.scrollback.len() > SCROLLBACK_MAX {
                    self.scrollback.pop_front();
                }
            } else {
                self.partial.push_str(piece);
            }
        }
        if self.view_offset > 0 {
            // browsing: view stays frozen, buffer keeps filling
            return Ok(());
        }
        write!(self.out, "\x1b8{}\x1b7", raw)?;
        self.draw_input()?;
        self.out.flush()
    }

    pub fn buffer_len(&self) -> usize {
        self.scrollback.len()
    }

    /// Iterate scrollback lines, oldest first (raw, with ANSI codes).
    pub fn buffer_lines(&self) -> impl DoubleEndedIterator<Item = &String> {
        self.scrollback.iter()
    }

    pub fn buffer_clear(&mut self) -> io::Result<()> {
        self.scrollback.clear();
        self.partial.clear();
        self.view_offset = 0;
        self.layout()
    }

    pub fn scroll_offset(&self) -> usize {
        self.view_offset
    }

    /// Move the view: negative = toward older lines (up), positive = toward
    /// live (down). `page` units of one page minus one line.
    pub fn buffer_page(&mut self, dir: i64) -> io::Result<()> {
        let page = self.out_rows().saturating_sub(1).max(1) as i64;
        self.buffer_scroll(dir * page)
    }

    pub fn buffer_scroll(&mut self, delta: i64) -> io::Result<()> {
        let max = self.scrollback.len().saturating_sub(1);
        let new = (self.view_offset as i64 - delta).clamp(0, max as i64) as usize;
        if new == self.view_offset {
            return Ok(());
        }
        self.view_offset = new;
        self.render_view()
    }

    pub fn buffer_home(&mut self) -> io::Result<()> {
        self.view_offset = self.scrollback.len().saturating_sub(1);
        self.render_view()
    }

    pub fn buffer_end(&mut self) -> io::Result<()> {
        if self.view_offset != 0 {
            self.view_offset = 0;
            self.render_view()?;
        }
        Ok(())
    }

    /// Jump so the view ends at buffer index `idx` (0-based).
    pub fn buffer_jump(&mut self, idx: usize) -> io::Result<()> {
        self.view_offset = self.scrollback.len().saturating_sub(1).saturating_sub(idx);
        self.render_view()
    }

    /// Redraw the output region for the current view offset.
    fn render_view(&mut self) -> io::Result<()> {
        write!(self.out, "\x1b[0m\x1b[1;{}r", self.out_rows())?;
        for r in 1..=self.out_rows() {
            write!(self.out, "\x1b[{};1H\x1b[2K", r)?;
        }
        write!(self.out, "\x1b[1;1H")?;
        let keep = self.out_rows() as usize;
        let end = self.scrollback.len().saturating_sub(self.view_offset);
        let start = end.saturating_sub(keep);
        let mut first = true;
        for i in start..end {
            if !first {
                write!(self.out, "\r\n")?;
            }
            first = false;
            write!(self.out, "{}\x1b[0m", self.scrollback[i])?;
        }
        if self.view_offset == 0 {
            if !first {
                write!(self.out, "\r\n")?;
            }
            write!(self.out, "{}", self.partial)?;
        }
        write!(self.out, "\x1b7")?;
        self.draw_status_bar()?;
        self.draw_input()?;
        self.out.flush()
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        self.cols = cols.max(10);
        self.rows = rows.max(4);
        self.view_offset = 0;
        write!(self.out, "\x1b[0m\x1b[2J\x1b[1;{}r\x1b[1;1H", self.out_rows())?;
        let keep = self.out_rows() as usize;
        let start = self.scrollback.len().saturating_sub(keep);
        for i in start..self.scrollback.len() {
            write!(self.out, "{}\x1b[0m\r\n", self.scrollback[i])?;
        }
        write!(self.out, "{}\x1b7", self.partial)?;
        self.draw_status_bar()?;
        self.draw_input()?;
        self.out.flush()
    }

    fn draw_input(&mut self) -> io::Result<()> {
        let row = self.rows;
        let width = self.cols as usize;
        let shown: String = if self.masked {
            self.input.chars().map(|_| '*').collect()
        } else {
            self.input.clone()
        };
        let cursor_chars = self.input[..self.cursor].chars().count();
        // horizontal scroll so the caret stays visible
        let offset = if width > 1 && cursor_chars >= width {
            cursor_chars + 1 - width
        } else {
            0
        };
        let visible: String = shown.chars().skip(offset).take(width.saturating_sub(1)).collect();
        let caret_col = cursor_chars.saturating_sub(offset) + 1;
        write!(
            self.out,
            "\x1b[{row};1H\x1b[0m\x1b[2K{visible}\x1b[{row};{caret_col}H"
        )
    }

    pub fn refresh_input(&mut self) -> io::Result<()> {
        self.draw_input()?;
        self.out.flush()
    }

    /// Full redraw (Ctrl-L).
    pub fn redraw(&mut self) -> io::Result<()> {
        self.resize(self.cols, self.rows)
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    pub fn history_clear(&mut self) {
        self.history.clear();
        self.hist_pos = None;
    }

    /// The word under construction at the cursor, for tab completion.
    pub fn current_word(&self) -> &str {
        let head = &self.input[..self.cursor];
        match head.rfind(char::is_whitespace) {
            Some(i) => &head[i + 1..],
            None => head,
        }
    }

    /// Replace the current word with `completion`.
    pub fn complete_word(&mut self, completion: &str) -> io::Result<()> {
        let head_len = self.current_word().len();
        let start = self.cursor - head_len;
        self.input.replace_range(start..self.cursor, completion);
        self.cursor = start + completion.len();
        self.refresh_input()
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> io::Result<InputResult> {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter => {
                let line = std::mem::take(&mut self.input);
                self.cursor = 0;
                self.hist_pos = None;
                if !line.trim().is_empty()
                    && self.history.last().map(|h| h.as_str()) != Some(line.as_str())
                    && !self.masked
                    && !line.starts_with(self.repeat_char)
                {
                    self.history.push(line.clone());
                }
                self.buffer_end()?;
                self.refresh_input()?;
                return Ok(InputResult::Submit(line));
            }
            KeyCode::Tab => return Ok(InputResult::Tab),
            KeyCode::PageUp => {
                self.buffer_page(-1)?;
                return Ok(InputResult::None);
            }
            KeyCode::PageDown => {
                self.buffer_page(1)?;
                return Ok(InputResult::None);
            }
            KeyCode::Esc => {
                self.buffer_end()?;
                return Ok(InputResult::None);
            }
            KeyCode::Char('d') if ctrl => {
                if self.input.is_empty() {
                    return Ok(InputResult::Quit);
                }
            }
            KeyCode::Char('c') if ctrl => {
                self.input.clear();
                self.cursor = 0;
                self.hist_pos = None;
            }
            KeyCode::Char('u') if ctrl => {
                self.input.drain(..self.cursor);
                self.cursor = 0;
            }
            KeyCode::Char('k') if ctrl => {
                self.input.truncate(self.cursor);
            }
            KeyCode::Char('w') if ctrl => {
                let head = &self.input[..self.cursor];
                let trimmed = head.trim_end();
                let cut = trimmed.rfind(char::is_whitespace).map(|i| i + 1).unwrap_or(0);
                self.input.replace_range(cut..self.cursor, "");
                self.cursor = cut;
            }
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.input.len(),
            KeyCode::Char('l') if ctrl => {
                self.redraw()?;
                return Ok(InputResult::None);
            }
            KeyCode::Char(c) if !ctrl => {
                self.input.insert(self.cursor, c);
                self.cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let prev = prev_char_boundary(&self.input, self.cursor);
                    self.input.replace_range(prev..self.cursor, "");
                    self.cursor = prev;
                }
            }
            KeyCode::Delete => {
                if self.cursor < self.input.len() {
                    let next = next_char_boundary(&self.input, self.cursor);
                    self.input.replace_range(self.cursor..next, "");
                }
            }
            KeyCode::Left => {
                if self.cursor > 0 {
                    self.cursor = prev_char_boundary(&self.input, self.cursor);
                }
            }
            KeyCode::Right => {
                if self.cursor < self.input.len() {
                    self.cursor = next_char_boundary(&self.input, self.cursor);
                }
            }
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.input.len(),
            KeyCode::Up => {
                if !self.history.is_empty() {
                    let pos = match self.hist_pos {
                        None => {
                            self.stash = self.input.clone();
                            self.history.len() - 1
                        }
                        Some(0) => 0,
                        Some(p) => p - 1,
                    };
                    self.hist_pos = Some(pos);
                    self.input = self.history[pos].clone();
                    self.cursor = self.input.len();
                }
            }
            KeyCode::Down => {
                if let Some(p) = self.hist_pos {
                    if p + 1 < self.history.len() {
                        self.hist_pos = Some(p + 1);
                        self.input = self.history[p + 1].clone();
                    } else {
                        self.hist_pos = None;
                        self.input = std::mem::take(&mut self.stash);
                    }
                    self.cursor = self.input.len();
                }
            }
            _ => {}
        }
        self.refresh_input()?;
        Ok(InputResult::None)
    }
}

impl Drop for SplitUi {
    fn drop(&mut self) {
        let _ = write!(self.out, "\x1b[0m\x1b[r\x1b[{};1H\r\n", self.rows);
        let _ = self.out.flush();
        let _ = terminal::disable_raw_mode();
    }
}

fn prev_char_boundary(s: &str, i: usize) -> usize {
    let mut i = i - 1;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn next_char_boundary(s: &str, i: usize) -> usize {
    let mut i = i + 1;
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}
