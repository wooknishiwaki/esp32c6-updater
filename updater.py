# -*- coding: utf-8 -*-
"""
ESP32C6 ポータブルアップデーター（Arduino互換版）
お客様の環境を汚さずにESP32C6のファームウェアをアップデートするツール
バイナリファイル書き込み履歴記録機能付き
"""

import os
import sys
import tkinter as tk
from tkinter import filedialog, ttk, messagebox, simpledialog
import tkinter.font
import threading
import subprocess
import tempfile
import shutil
import zipfile
import time
import socket
import json
import fcntl
import psutil
import csv
import hashlib
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# シングルインスタンス制御用のロックファイル
LOCK_FILE = None

def is_already_running():
    """
    アプリケーションが既に起動しているかチェック
    """
    current_process = psutil.Process()
    current_name = "ESP32C6 Updater"
    
    for proc in psutil.process_iter(['name', 'pid']):
        try:
            # 自分自身は除外
            if proc.pid == current_process.pid:
                continue
                
            # プロセス名をチェック
            if proc.info['name'] == current_name:
                return True
                
            # macOSアプリケーションバンドルの場合
            if proc.info['name'].endswith('ESP32C6 Updater'):
                return True
                
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return False

def cleanup_lock():
    """
    ロックファイルのクリーンアップ
    """
    global LOCK_FILE
    if LOCK_FILE:
        try:
            fcntl.flock(LOCK_FILE.fileno(), fcntl.LOCK_UN)
            LOCK_FILE.close()
            os.unlink(LOCK_FILE.name)
        except:
            pass

# esptoolのパスを設定
TOOL_ROOT = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
LIB_PATH = os.path.join(TOOL_ROOT, 'lib')
ESPTOOL_PATH = os.path.join(LIB_PATH, 'esptool.py')

# esptoolのパスをsys.pathに追加
if LIB_PATH not in sys.path:
    sys.path.append(LIB_PATH)

class FlashHistoryManager:
    """フラッシュ書き込み履歴管理クラス"""
    
    def __init__(self, app_dir):
        self.app_dir = app_dir
        self.history_file = os.path.join(app_dir, "flash_history.csv.enc")
        self.password = None
        self.cipher_suite = None
        
    def _derive_key_from_password(self, password, salt):
        """パスワードから暗号化キーを生成"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _get_password(self, for_read=True):
        """パスワードを取得"""
        if for_read and os.path.exists(self.history_file):
            title = "履歴ファイル読み込み"
            prompt = "履歴ファイルのパスワードを入力してください："
        else:
            title = "履歴ファイル作成"
            prompt = "履歴ファイル用のパスワードを設定してください："
            
        password = simpledialog.askstring(title, prompt, show='*')
        return password
    
    def _encrypt_data(self, data, password):
        """データを暗号化"""
        salt = os.urandom(16)
        key = self._derive_key_from_password(password, salt)
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(data.encode())
        return salt + encrypted_data
    
    def _decrypt_data(self, encrypted_data, password):
        """データを復号化"""
        salt = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]
        key = self._derive_key_from_password(password, salt)
        cipher_suite = Fernet(key)
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_content)
            return decrypted_data.decode()
        except Exception:
            raise ValueError("パスワードが間違っているか、ファイルが破損しています")
    
    def read_history(self):
        """履歴を読み込み"""
        if not os.path.exists(self.history_file):
            return []
        
        password = self._get_password(for_read=True)
        if not password:
            return None
        
        try:
            with open(self.history_file, 'rb') as f:
                encrypted_data = f.read()
            
            csv_content = self._decrypt_data(encrypted_data, password)
            
            # CSVデータをパース
            history = []
            reader = csv.reader(csv_content.strip().split('\n'))
            for row in reader:
                if len(row) >= 3:
                    try:
                        count = int(row[0])
                        date_str = row[1]
                        filename = row[2]
                        history.append((count, date_str, filename))
                    except ValueError:
                        continue
            
            self.password = password
            return history
            
        except Exception as e:
            messagebox.showerror("エラー", f"履歴ファイルの読み込みに失敗しました: {str(e)}")
            return None
    
    def write_history(self, history):
        """履歴を書き込み"""
        if not self.password:
            password = self._get_password(for_read=False)
            if not password:
                return False
            self.password = password
        
        try:
            # CSVデータを作成
            csv_content = ""
            for count, date_str, filename in history:
                csv_content += f"{count},{date_str},{filename}\n"
            
            # 暗号化して保存
            encrypted_data = self._encrypt_data(csv_content, self.password)
            
            with open(self.history_file, 'wb') as f:
                f.write(encrypted_data)
            
            return True
            
        except Exception as e:
            messagebox.showerror("エラー", f"履歴ファイルの書き込みに失敗しました: {str(e)}")
            return False
    
    def add_flash_record(self, binary_filename):
        """フラッシュ書き込み記録を追加"""
        # 現在の履歴を読み込み
        history = self.read_history()
        if history is None:
            # パスワード入力がキャンセルされた場合
            return False
        
        # 新しい記録を追加
        now = datetime.now()
        date_str = now.strftime("%Y-%m-%d %H:%M:%S JST")
        next_count = len(history) + 1
        
        history.append((next_count, date_str, binary_filename))
        
        # 履歴を保存
        return self.write_history(history)
    
    def show_history(self):
        """履歴を表示"""
        history = self.read_history()
        if history is None:
            return
        
        if not history:
            messagebox.showinfo("履歴", "書き込み履歴はありません。")
            return
        
        # 履歴表示ウィンドウを作成
        history_window = tk.Toplevel()
        history_window.title("フラッシュ書き込み履歴")
        history_window.geometry("800x400")
        
        # ツリービューで表示
        columns = ("回数", "記録日時", "バイナリファイル名")
        tree = ttk.Treeview(history_window, columns=columns, show='headings')
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=200)
        
        # 履歴データを追加（新しい順）
        for count, date_str, filename in reversed(history):
            tree.insert('', 'end', values=(count, date_str, filename))
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 閉じるボタン
        close_btn = tk.Button(history_window, text="閉じる", 
                             command=history_window.destroy)
        close_btn.pack(pady=5)

class ESP32C6Updater:
    def __init__(self, root):
        self.root = root
        self.root.title("ESP32C6 ファームウェアアップデーター")
        self.root.geometry("800x850")  # 高さを少し増やす
        self.root.resizable(True, True)
        
        # 履歴管理器を初期化
        app_dir = os.path.dirname(os.path.abspath(__file__))
        if getattr(sys, 'frozen', False):
            app_dir = os.path.dirname(sys.executable)
        self.history_manager = FlashHistoryManager(app_dir)
        
        # 変数の初期化
        self.binary_path = tk.StringVar()
        self.port = tk.StringVar()
        self.baud_rate = tk.StringVar(value="230400")
        self.flash_mode = tk.StringVar(value="qio")     # Arduinoデフォルト値
        self.flash_size = tk.StringVar(value="8MB")     # Arduinoデフォルト値
        self.flash_freq = tk.StringVar(value="80m")
        self.flash_addr = tk.StringVar(value="0x10000")
        
        # 埋め込みバイナリのリストを取得
        self.embedded_binaries = []
        
        # UIの構築
        self._build_ui()
        
        # COMポートの自動検出
        self.detect_ports()
    
    def _build_ui(self):
        """UIを構築"""
        # macOS用のフォーカス修正
        if sys.platform == 'darwin':
            self.root.tk.call('tk', 'scaling', 1.0)
            self.root.lift()
            self.root.attributes('-topmost', True)
            self.root.after_idle(lambda: self.root.attributes('-topmost', False))
        
        # メインフレーム
        main_frame = tk.Frame(self.root, padx=10, pady=10, background='#f0f0f0')
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # バイナリファイル選択
        file_frame = tk.LabelFrame(main_frame, text="バイナリファイル", padx=5, pady=5, 
                                  font=('Helvetica', 12), bg='#f0f0f0',
                                  relief=tk.GROOVE, bd=2)
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.binary_entry = tk.Entry(file_frame, textvariable=self.binary_path, width=50,
                                    font=('Helvetica', 12), bd=2, relief=tk.SUNKEN)
        self.binary_entry.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        
        browse_button = tk.Button(file_frame, text="参照...", 
                                 command=self.browse_binary,
                                 font=('Helvetica', 12),
                                 bg='#e0e0e0', relief=tk.RAISED, bd=2)
        browse_button.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # ポート設定
        port_frame = tk.LabelFrame(main_frame, text="シリアルポート設定", padx=5, pady=5,
                                  font=('Helvetica', 12), bg='#f0f0f0',
                                  relief=tk.GROOVE, bd=2)
        port_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(port_frame, text="ポート:", bg='#f0f0f0', font=('Helvetica', 12)).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        # COMポートドロップダウン
        self.port_combo = tk.OptionMenu(port_frame, self.port, "")
        self.port_combo.config(font=('Helvetica', 12), bg='#e0e0e0', relief=tk.RAISED, bd=2)
        self.port_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        update_button = tk.Button(port_frame, text="更新", command=self.detect_ports,
                                 font=('Helvetica', 12), bg='#e0e0e0',
                                 relief=tk.RAISED, bd=2)
        update_button.grid(row=0, column=2, padx=5, pady=5)
        
        tk.Label(port_frame, text="ボーレート:", bg='#f0f0f0', font=('Helvetica', 12)).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        
        # ボーレートドロップダウン
        baud_values = ["115200", "230400", "460800", "921600"]
        self.baud_combo = tk.OptionMenu(port_frame, self.baud_rate, *baud_values)
        self.baud_combo.config(font=('Helvetica', 12), bg='#e0e0e0', relief=tk.RAISED, bd=2)
        self.baud_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # フラッシュ設定
        flash_frame = tk.LabelFrame(main_frame, text="フラッシュ設定", padx=5, pady=5,
                                   font=('Helvetica', 12), bg='#f0f0f0',
                                   relief=tk.GROOVE, bd=2)
        flash_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(flash_frame, text="フラッシュモード:", bg='#f0f0f0', font=('Helvetica', 12)).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        # フラッシュモードドロップダウン
        mode_values = ["dio", "qio", "dout", "qout"]
        self.mode_combo = tk.OptionMenu(flash_frame, self.flash_mode, *mode_values)
        self.mode_combo.config(font=('Helvetica', 12), bg='#e0e0e0', relief=tk.RAISED, bd=2)
        self.mode_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        tk.Label(flash_frame, text="フラッシュ周波数:", bg='#f0f0f0', font=('Helvetica', 12)).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        
        # フラッシュ周波数ドロップダウン
        freq_values = ["40m", "80m"]
        self.freq_combo = tk.OptionMenu(flash_frame, self.flash_freq, *freq_values)
        self.freq_combo.config(font=('Helvetica', 12), bg='#e0e0e0', relief=tk.RAISED, bd=2)
        self.freq_combo.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        
        tk.Label(flash_frame, text="フラッシュサイズ:", bg='#f0f0f0', font=('Helvetica', 12)).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        
        # フラッシュサイズドロップダウン
        size_values = ["2MB", "4MB", "8MB", "16MB"]
        self.size_combo = tk.OptionMenu(flash_frame, self.flash_size, *size_values)
        self.size_combo.config(font=('Helvetica', 12), bg='#e0e0e0', relief=tk.RAISED, bd=2)
        self.size_combo.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        tk.Label(flash_frame, text="開始アドレス:", bg='#f0f0f0', font=('Helvetica', 12)).grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        
        # 開始アドレスドロップダウン
        addr_values = ["0x0", "0x1000", "0x8000", "0x10000"]
        self.addr_combo = tk.OptionMenu(flash_frame, self.flash_addr, *addr_values)
        self.addr_combo.config(font=('Helvetica', 12), bg='#e0e0e0', relief=tk.RAISED, bd=2)
        self.addr_combo.grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)
        
        # Arduino用プリセットボタンの追加
        preset_frame = tk.Frame(flash_frame, bg='#f0f0f0')
        preset_frame.grid(row=2, column=0, columnspan=4, padx=5, pady=5, sticky=tk.W)
        
        tk.Label(preset_frame, text="プリセット:", bg='#f0f0f0', font=('Helvetica', 12)).pack(side=tk.LEFT, padx=5)
        
        arduino_button = tk.Button(preset_frame, text="Arduino ESP32C6", 
                                  command=self.set_arduino_preset,
                                  font=('Helvetica', 12), bg='#e0e0e0',
                                  relief=tk.RAISED, bd=2)
        arduino_button.pack(side=tk.LEFT, padx=5)
        
        standard_button = tk.Button(preset_frame, text="標準 ESP32C6", 
                                   command=self.set_standard_preset,
                                   font=('Helvetica', 12), bg='#e0e0e0',
                                   relief=tk.RAISED, bd=2)
        standard_button.pack(side=tk.LEFT, padx=5)
        
        # 履歴ボタンを追加
        history_button = tk.Button(preset_frame, text="書き込み履歴", 
                                  command=self.show_flash_history,
                                  font=('Helvetica', 12), bg='#e0e0e0',
                                  relief=tk.RAISED, bd=2)
        history_button.pack(side=tk.LEFT, padx=5)
        
        # ログ表示エリア
        log_frame = tk.LabelFrame(main_frame, text="ログ", padx=5, pady=5,
                                 font=('Helvetica', 12), bg='#f0f0f0',
                                 relief=tk.GROOVE, bd=2)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = tk.Text(log_frame, height=15, wrap=tk.WORD, 
                              font=("Courier", 11),
                              bg='white', relief=tk.SUNKEN, bd=2)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(log_frame, command=self.log_text.yview,
                               relief=tk.RAISED, bd=2)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)
        
        # 進捗バー
        self.progress = tk.Canvas(main_frame, height=20, bg='#f0f0f0', bd=0, highlightthickness=0)
        self.progress.pack(fill=tk.X, padx=5, pady=5)
        self.progress_bar = self.progress.create_rectangle(0, 0, 0, 20, fill='#007bff', width=0)
        self.is_progressing = False
        
        # 操作ボタン
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # 左側のボタン
        left_frame = tk.Frame(button_frame, bg='#f0f0f0')
        left_frame.pack(side=tk.LEFT, fill=tk.X)
        
        test_button = tk.Button(left_frame, text="接続テスト", 
                               command=self.test_connection,
                               font=('Helvetica', 12), bg='#e0e0e0',
                               relief=tk.RAISED, bd=2)
        test_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        info_button = tk.Button(left_frame, text="チップ情報", 
                               command=self.chip_info,
                               font=('Helvetica', 12), bg='#e0e0e0',
                               relief=tk.RAISED, bd=2)
        info_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        erase_button = tk.Button(left_frame, text="消去", 
                                command=self.erase_flash,
                                font=('Helvetica', 12), bg='#e0e0e0',
                                relief=tk.RAISED, bd=2)
        erase_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        # 右側のボタン（実行ボタン）- テキスト色を黒に変更
        flash_button = tk.Button(button_frame, text="ファームウェア書き込み実行", 
                                command=self.write_flash, 
                                font=('Helvetica', 13, 'bold'),
                                bg='#007bff', fg='black',  # テキスト色を黒に変更
                                activebackground='#0069d9', activeforeground='black',
                                relief=tk.RAISED, bd=2, padx=10, pady=5)
        flash_button.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # 初期メッセージをログに表示
        self.log("ESP32C6 ファームウェアアップデーターを起動しました")
        self.log("バイナリファイルを選択し、シリアルポートを選択して「ファームウェア書き込み実行」ボタンをクリックしてください")
    
    def show_flash_history(self):
        """フラッシュ書き込み履歴を表示"""
        self.history_manager.show_history()
    
    def update_progress(self):
        """進捗バーを更新"""
        if not self.is_progressing:
            return
            
        width = self.progress.winfo_width()
        position = self.progress.coords(self.progress_bar)[2]
        if position >= width:
            position = 0
        else:
            position += 5
            
        self.progress.coords(self.progress_bar, 0, 0, position, 20)
        self.root.after(50, self.update_progress)
    
    def start_progress(self):
        """進捗表示を開始"""
        self.is_progressing = True
        self.update_progress()
    
    def stop_progress(self):
        """進捗表示を停止"""
        self.is_progressing = False
        self.progress.coords(self.progress_bar, 0, 0, 0, 20)
    
    def set_arduino_preset(self):
        """Arduino ESP32C6用のプリセットを設定"""
        self.flash_mode.set("qio")      # 正しい値に修正
        self.flash_size.set("8MB")      # 正しい値に修正
        self.flash_freq.set("80m")
        self.flash_addr.set("0x10000")
        self.log("Arduino ESP32C6プリセットを適用しました")
    
    def set_standard_preset(self):
        """標準ESP32C6用のプリセットを設定"""
        self.flash_mode.set("dio")
        self.flash_size.set("4MB")
        self.flash_freq.set("40m")
        self.flash_addr.set("0x0")
        self.log("標準ESP32C6プリセットを適用しました")
    
    def detect_arduino_binary(self, file_path):
        """Arduinoで生成されたバイナリファイルかを推測"""
        try:
            with open(file_path, 'rb') as f:
                # ESP32のArduinoバイナリは特定のヘッダを持つことが多い
                header = f.read(4)
                # ESP32バイナリのマジックナンバー (E9)を確認
                if header[0] == 0xE9:
                    return True
            return False
        except Exception:
            return False
    
    def detect_ports(self):
        """利用可能なシリアルポートを検出"""
        self.log("シリアルポートを検索中...")
        self.start_progress()
        
        def _detect():
            try:
                # 検出されたポートのリストを解析
                ports = []
                
                # macOS: シリアルポートの検出
                if sys.platform == 'darwin':
                    import glob
                    # USBシリアルデバイスの一般的なパターン
                    usb_patterns = [
                        '/dev/cu.*',          # すべてのcuデバイス
                        '/dev/tty.*',         # すべてのttyデバイス
                        '/dev/cu.usb*',       # USBシリアル
                        '/dev/cu.usbserial*', # FTDI
                        '/dev/cu.SLAB*',      # Silicon Labs
                        '/dev/cu.wchusbserial*', # CH340
                        '/dev/cu.CP210*',     # Silicon Labs CP210x
                        '/dev/cu.modem*',     # モデムデバイス
                        '/dev/tty.usb*',      # 代替パス
                        '/dev/tty.usbserial*',
                        '/dev/tty.SLAB*',
                        '/dev/tty.wchusbserial*',
                        '/dev/tty.CP210*',
                        '/dev/tty.modem*'
                    ]
                    
                    # 各パターンで検索
                    for pattern in usb_patterns:
                        found = glob.glob(pattern)
                        if found:
                            self.log(f"パターン {pattern} で {len(found)} 個のポートを検出")
                            ports.extend(found)
                    
                    # 重複を除去
                    ports = list(set(ports))
                    
                    # デバッグ情報
                    if not ports:
                        self.log("シリアルデバイスが見つかりませんでした")
                        self.log("利用可能なデバイス:")
                        all_devices = glob.glob('/dev/cu.*') + glob.glob('/dev/tty.*')
                        for device in all_devices:
                            self.log(f"  - {device}")
                
                # Windows: COMポートの検出
                else:
                    try:
                        import serial.tools.list_ports
                        ports = [p.device for p in serial.tools.list_ports.comports()]
                        if ports:
                            self.log(f"Windowsで {len(ports)} 個のCOMポートを検出")
                            for port in ports:
                                self.log(f"  - {port}")
                    except ImportError:
                        self.log("pyserialがインストールされていません。pip install pyserialでインストールしてください。")
                        ports = []
                    except Exception as e:
                        self.log(f"シリアルポート検出エラー: {str(e)}")
                        ports = []
                
                self.root.after(0, lambda: self._update_ports(ports))
            except Exception as e:
                self.log(f"予期せぬエラー: {str(e)}")
                import traceback
                self.log(traceback.format_exc())
            finally:
                self.root.after(0, self.stop_progress)
        
        threading.Thread(target=_detect, daemon=True).start()
    
    def _update_ports(self, ports):
        """ポートリストを更新"""
        try:
            # メニューをクリア
            self.port_combo['menu'].delete(0, 'end')
            
            # 新しいポートを追加
            for port in sorted(ports):  # ポートをソートして追加
                self.port_combo['menu'].add_command(
                    label=port,
                    command=lambda p=port: self.port.set(p)
                )
            
            if ports:
                # 現在選択されているポートが新しいリストにない場合は、最初のポートを選択
                if self.port.get() not in ports:
                    self.port.set(ports[0])
                self.log(f"{len(ports)}個のシリアルポートが見つかりました")
                # 検出されたポートの一覧を表示
                for port in sorted(ports):
                    self.log(f"  - {port}")
            else:
                self.log("シリアルポートが見つかりませんでした")
        except Exception as e:
            self.log(f"ポートリスト更新エラー: {str(e)}")
            import traceback
            self.log(traceback.format_exc())
    
    def browse_binary(self):
        """バイナリファイルを選択"""
        filename = filedialog.askopenfilename(
            title="バイナリファイルを選択",
            filetypes=[("バイナリファイル", "*.bin"), ("すべてのファイル", "*.*")]
        )
        if filename:
            self.binary_path.set(filename)
            self.log(f"ファイルを選択: {filename}")
            
            # Arduino生成バイナリの自動検出
            if self.detect_arduino_binary(filename):
                self.log("Arduinoで生成されたバイナリと思われます。Arduino設定を推奨します。")
                if messagebox.askyesno("Arduino検出", "このバイナリはArduinoで生成されたものと思われます。\nArduino用の推奨設定に変更しますか？"):
                    self.set_arduino_preset()
    
    def log(self, message):
        """ログメッセージを表示"""
        timestamp = time.strftime("%H:%M:%S", time.localtime())
        formatted_message = f"[{timestamp}] {message}"
        self.log_text.insert(tk.END, formatted_message + "\n")
        self.log_text.see(tk.END)
        
        # コンソールにも出力（デバッグ用）
        print(formatted_message)
    
    def run_esptool(self, args, callback=None):
        """esptoolを実行"""
        self.start_progress()

        def _run():
            process = None
            try:
                # アプリケーションバンドルのパスを取得
                if getattr(sys, 'frozen', False):
                    bundle_dir = os.path.dirname(sys.executable)
                    if sys.platform == 'darwin':
                        # macOSの場合、Contents/MacOS/からContents/Resources/へ
                        resources_dir = os.path.join(os.path.dirname(os.path.dirname(bundle_dir)), 'Resources')
                        esptool_path = os.path.join(resources_dir, 'esptool.py')
                    else:
                        # Windows/Linuxの場合
                        esptool_path = os.path.join(bundle_dir, 'esptool.py')
                else:
                    # 開発環境での実行
                    esptool_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'esptool.py')

                # 基本コマンド (esptool本体)
                cmd = [sys.executable, esptool_path]
                
                # 共通オプション（操作の前に必要なもの）
                cmd.extend([
                    "--chip", "esp32c6",
                    "--port", self.port.get(),
                    "--baud", self.baud_rate.get(),
                    "--before", "default_reset",  # デフォルトのリセット動作
                    "--after", "hard_reset"       # 書き込み後のリセット動作
                ])
                
                # 操作コマンドとそのパラメータを追加
                cmd.extend(args)
                
                self.root.after(0, lambda: self.log(f"コマンド実行: {' '.join(cmd)}"))
                
                # Windowsでコンソールウィンドウが表示されるのを防ぐ
                startupinfo = None
                if sys.platform == 'win32':
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE

                # macOSの場合、シリアルポートの権限をチェック
                if sys.platform == 'darwin':
                    port = self.port.get()
                    if not os.access(port, os.R_OK | os.W_OK):
                        self.root.after(0, lambda: self.log(f"警告: シリアルポート {port} にアクセス権限がありません"))
                        self.root.after(0, lambda: messagebox.showerror("エラー", 
                            f"シリアルポート {port} にアクセス権限がありません。\n"
                            "以下のコマンドを実行して権限を付与してください：\n"
                            f"sudo chown {os.getlogin()} {port}"))
                        return

                # サブプロセスを作成
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    startupinfo=startupinfo,
                    bufsize=1  # 行バッファリング
                )

                # 非同期で出力を読み取る
                def read_output(pipe, is_error=False):
                    for line in iter(pipe.readline, ''):
                        if line:
                            prefix = "エラー: " if is_error else ""
                            self.root.after(0, lambda l=line: self.log(f"{prefix}{l.strip()}"))
                    pipe.close()

                # 出力読み取りスレッドを開始
                import threading
                stdout_thread = threading.Thread(target=read_output, args=(process.stdout,), daemon=True)
                stderr_thread = threading.Thread(target=read_output, args=(process.stderr, True), daemon=True)
                stdout_thread.start()
                stderr_thread.start()

                # プロセスの終了を待つ
                process.wait()

                # 出力読み取りスレッドの終了を待つ
                stdout_thread.join(timeout=5)
                stderr_thread.join(timeout=5)

                if process.returncode == 0:
                    self.root.after(0, lambda: self.log("コマンド実行完了"))
                    if callback:
                        self.root.after(0, callback)
                else:
                    error_msg = "コマンド実行エラー"
                    stderr_output = process.stderr.read() if process.stderr else ""
                    if "No serial data received" in stderr_output:
                        error_msg = (
                            "ESP32-C6との接続に失敗しました。以下を確認してください：\n"
                            "1. デバイスが正しく接続されているか\n"
                            "2. ボーレートが適切か（115200を試してください）\n"
                            "3. ESP32-C6がブートモードになっているか\n"
                            "   - BOOTボタンを押しながら\n"
                            "   - ENボタンを押して離す\n"
                            "   - BOOTボタンを離す\n"
                            "4. USBケーブルがデータ転送対応か"
                        )
                    self.root.after(0, lambda: self.log(f"{error_msg}: 終了コード {process.returncode}"))
                    self.root.after(0, lambda: messagebox.showerror("エラー", error_msg))

            except Exception as e:
                self.root.after(0, lambda: self.log(f"esptool実行エラー: {str(e)}"))
                self.root.after(0, lambda: messagebox.showerror("エラー", f"esptool実行エラー: {str(e)}"))
            finally:
                # プロセスが残っている場合は強制終了
                if process and process.poll() is None:
                    try:
                        process.terminate()
                        process.wait(timeout=5)
                    except:
                        if process.poll() is None:
                            process.kill()
                self.root.after(0, self.stop_progress)
        
        threading.Thread(target=_run, daemon=True).start()
            
    def test_connection(self):
        """接続テスト"""
        if not self.port.get():
            messagebox.showerror("エラー", "ポートを選択してください")
            return
        
        self.log("接続テスト開始...")
        self.run_esptool(["read_mac"])
    
    def chip_info(self):
        """チップ情報取得"""
        if not self.port.get():
            messagebox.showerror("エラー", "ポートを選択してください")
            return
        
        self.log("チップ情報取得開始...")
        self.run_esptool(["chip_id"])
    
    def erase_flash(self):
        """フラッシュ消去"""
        if not self.port.get():
            messagebox.showerror("エラー", "ポートを選択してください")
            return
        
        if messagebox.askyesno("確認", "フラッシュを消去しますか？この操作は元に戻せません。"):
            self.log("フラッシュ消去開始...")
            self.run_esptool(["erase_flash"])

    def write_flash(self):
        """ファームウェア書き込み"""
        if not self.port.get():
            messagebox.showerror("エラー", "ポートを選択してください")
            return
        
        binary_path_val = self.binary_path.get()
        if not binary_path_val or not os.path.exists(binary_path_val):
            messagebox.showerror("エラー", "有効なバイナリファイルを選択してください")
            return
        
        app_binary_filename = os.path.basename(binary_path_val) # ファイル名を取得

        # --- merged.bin の特別処理を追加 ---
        if app_binary_filename.endswith(".ino.merged.bin") or app_binary_filename.endswith(".merged.bin"):
            self.log(f"Mergedバイナリファイル ({app_binary_filename}) が検出されました。アドレス0x0に単一ファイルとして書き込みます。")
            if messagebox.askyesno("Mergedバイナリ確認",
                                   f"ファイル '{app_binary_filename}' は結合バイナリファイルのようです。\n"
                                   "これをアドレス 0x0 に書き込みますか？\n"
                                   "(これによりフラッシュ全体が上書きされます)"):
                write_strategy = "merged_bin"
                # merged.binの場合、通常他のフラッシュ設定はesptoolが自動で行うか、
                # バイナリ自体に含まれる情報で足りるが、念のため現在の設定を使用する。
                # ユーザーがプリセット等で設定変更できるようにしておく。
            else:
                self.log("Mergedバイナリの書き込みがキャンセルされました。")
                return
        else:
            # merged.bin でない場合の既存のロジック
            is_arduino_binary = self.detect_arduino_binary(binary_path_val)
            self.log(f"Arduinoバイナリ検出結果: {is_arduino_binary} (ファイル: {binary_path_val})")

            if is_arduino_binary:
                if self.flash_mode.get() != "qio" or \
                   self.flash_size.get() != "8MB" or \
                   self.flash_addr.get() != "0x10000":
                    self.log("現在の設定がArduino推奨値と異なります。プリセット適用を提案します。")
                    if messagebox.askyesno("Arduino検出", 
                                           "このバイナリはArduinoで生成されたものと思われます。\n"
                                           "Arduino用の推奨設定に変更しますか？\n"
                                           "(モード:qio, サイズ:8MB, 周波数:80m, アドレス:0x10000)"):
                        self.set_arduino_preset()

            write_strategy = "app_only" 

            if is_arduino_binary:
                self.log("Arduinoバイナリとして処理。書き込み方法の選択ダイアログを表示します。")
                choice = messagebox.askyesnocancel(
                    "書き込み方法の選択", 
                    "Arduinoバイナリが検出されました。書き込み方法を選択してください。\n\n"
                    "「はい」: Arduino互換の個別ファイル完全書き込み\n"
                    "「いいえ」: アプリケーションのみ書き込み\n"
                    "「キャンセル」: 中止",
                    icon=messagebox.QUESTION
                )
                
                if choice is None:
                    self.log("書き込みがキャンセルされました。")
                    return
                elif choice:
                    write_strategy = "arduino_full" # 個別ファイル書き込み
                else:
                    write_strategy = "app_only"
            else:
                self.log("Arduinoバイナリとして検出されなかったか、ユーザーがアプリのみ書き込みを選択しました。")
                if not is_arduino_binary:
                     write_strategy = "single_file" # Arduinoでないなら明確にsingle_file

        self.log(f"最終的に決定された書き込み戦略: {write_strategy}")

        # --- merged_bin でない場合の追加チェック ---
        if write_strategy != "merged_bin":
            if write_strategy == "app_only" and self.flash_addr.get() != "0x10000":
                self.log(f"アプリケーションのみ書き込みで、開始アドレスが {self.flash_addr.get()} です。0x10000への変更を提案します。")
                if messagebox.askyesno("設定確認", 
                                       f"アプリケーションのみ書き込みますが、開始アドレスが {self.flash_addr.get()} に設定されています。\n"
                                       "Arduino環境では通常 0x10000 です。0x10000 に変更しますか？"):
                    self.flash_addr.set("0x10000")
                    self.log("開始アドレスを0x10000に変更しました。")

            if write_strategy != "arduino_full" and self.flash_addr.get() == "0x0":
                self.log(f"書き込み戦略 {write_strategy} で開始アドレスが0x0です。ブートローダー上書き警告を表示します。")
                if not messagebox.askyesno("警告", "開始アドレス 0x0 は通常ブートローダーの領域です。\n"
                                                 "このまま書き込むとデバイスが起動しなくなる可能性があります。\n続行しますか？"):
                    self.log("ブートローダー上書きの警告により、書き込みを中止しました。")
                    return
        
        self.log(f"ファームウェア書き込み開始... (戦略: {write_strategy})")
        
        args = ["write_flash"]
        
        # write_strategy によってフラッシュパラメータの扱いを変える
        if write_strategy == "arduino_full" or write_strategy == "merged_bin":
            self.log(f"戦略 {write_strategy}: esptoolの自動検出に任せるため、明示的なフラッシュパラメータは省略します。")
            # この場合は、--flash_mode, --flash_freq, --flash_size を args に追加しない
        else:
            # app_only や single_file の場合は、GUIの設定値を渡す
            self.log(f"戦略 {write_strategy}: GUIで設定されたフラッシュパラメータを使用します。")
            args.extend([
                "--flash_mode", self.flash_mode.get(),
                "--flash_freq", self.flash_freq.get(),
                "--flash_size", self.flash_size.get()
            ])
            self.log(f"esptool共通フラッシュオプション: {' '.join(args[1:])}") # args[0]は"write_flash"なので

        if write_strategy == "merged_bin":
            self.log(f"Mergedバイナリ ({binary_path_val}) をアドレス 0x0 に書き込みます。")
            # merged.bin の場合はアドレスを強制的に 0x0 にする
            args.extend(["0x0", binary_path_val])

        elif write_strategy == "arduino_full":
            self.log("Arduino互換の個別ファイル完全書き込み処理を開始します...")
            app_binary_path = binary_path_val
            binary_dir = os.path.dirname(app_binary_path)
            
            current_app_binary_filename = os.path.basename(app_binary_path) # ローカル変数名変更
            self.log(f"アプリケーションバイナリファイル名: {current_app_binary_filename}")

            bootloader_filename = ""
            partitions_filename = ""
            boot_app0_prefix_candidate = ""

            if current_app_binary_filename.endswith(".ino.bin"):
                base_for_related_files = current_app_binary_filename[:-len(".bin")]
                bootloader_filename = f"{base_for_related_files}.bootloader.bin"
                partitions_filename = f"{base_for_related_files}.partitions.bin"
                boot_app0_prefix_candidate = base_for_related_files
            else:
                name_prefix_fallback = os.path.splitext(current_app_binary_filename)[0]
                bootloader_filename = f"{name_prefix_fallback}.bootloader.bin"
                partitions_filename = f"{name_prefix_fallback}.partitions.bin"
                boot_app0_prefix_candidate = name_prefix_fallback
                self.log(f"警告: アプリケーションファイル名が標準的な '.ino.bin' 形式ではありません。関連ファイル名を推測します: {name_prefix_fallback}")

            bootloader_bin_path = os.path.join(binary_dir, bootloader_filename)
            partitions_bin_path = os.path.join(binary_dir, partitions_filename)
            
            self.log(f"期待されるブートローダーファイルパス: {bootloader_bin_path}")
            self.log(f"期待されるパーティションファイルパス: {partitions_bin_path}")

            boot_app_bin_candidates = [
                os.path.join(binary_dir, "boot_app0.bin"),
                os.path.join(binary_dir, f"{boot_app0_prefix_candidate}.boot_app0.bin"),
            ]
            
            boot_app_bin_path = None
            for candidate in boot_app_bin_candidates:
                if os.path.exists(candidate):
                    boot_app_bin_path = candidate
                    self.log(f"boot_app0ファイルとして {candidate} を使用します。")
                    break
            if not boot_app_bin_path:
                self.log("boot_app0.bin (または関連名ファイル) が見つかりませんでした。")

            files_to_flash_map = {}

            if os.path.exists(bootloader_bin_path):
                self.log(f"ブートローダーファイル: {bootloader_bin_path}")
                files_to_flash_map["0x0"] = bootloader_bin_path
            else:
                self.log(f"エラー: ブートローダーファイルが見つかりません: {bootloader_bin_path}")
                messagebox.showerror("エラー", f"ブートローダーファイルが見つかりません:\n{bootloader_bin_path}")
                return
            
            if os.path.exists(partitions_bin_path):
                self.log(f"パーティションテーブルファイル: {partitions_bin_path}")
                files_to_flash_map["0x8000"] = partitions_bin_path
            else:
                self.log(f"エラー: パーティションテーブルファイルが見つかりません: {partitions_bin_path}")
                messagebox.showerror("エラー", f"パーティションテーブルファイルが見つかりません:\n{partitions_bin_path}")
                return
            
            if boot_app_bin_path:
                self.log(f"OTAデータファイル (boot_app0): {boot_app_bin_path}")
                files_to_flash_map["0xe000"] = boot_app_bin_path
            else:
                self.log("boot_app0.bin が見つからなかったため、OTAデータ領域の書き込みはスキップされます。")

            self.log(f"アプリケーションファイル: {app_binary_path}")
            files_to_flash_map["0x10000"] = app_binary_path

            sorted_flash_args = []
            for addr in sorted(files_to_flash_map.keys(), key=lambda x: int(x, 16)):
                sorted_flash_args.extend([addr, files_to_flash_map[addr]])
            
            args.extend(sorted_flash_args)

        elif write_strategy == "app_only":
            current_flash_addr = self.flash_addr.get()
            self.log(f"アプリケーション ({binary_path_val}) のみをアドレス {current_flash_addr} に書き込みます...")
            args.extend([current_flash_addr, binary_path_val])

        elif write_strategy == "single_file": # Arduinoバイナリでない場合
            current_flash_addr = self.flash_addr.get()
            self.log(f"単一ファイル ({binary_path_val}) をアドレス {current_flash_addr} に書き込みます...")
            args.extend([current_flash_addr, binary_path_val])
        
        else:
            self.log(f"致命的エラー: 不明な書き込み戦略です: {write_strategy}")
            messagebox.showerror("内部エラー", f"不明な書き込み戦略: {write_strategy}")
            return

        self.log(f"最終的なesptool引数 (write_flash以降): {' '.join(args[1:])}")
        
        # 書き込み成功時のコールバック関数を定義
        def on_flash_success():
            # 書き込み成功時に履歴を記録
            if self.history_manager.add_flash_record(app_binary_filename):
                self.log("書き込み履歴を記録しました")
            else:
                self.log("書き込み履歴の記録に失敗しました")
        
        self.run_esptool(args, callback=on_flash_success)

# "ESP32C6 ファームウェアアップデーター について" のための関数 (グローバルスコープ)
def show_about_dialog():
    # main関数内で設定するアプリ名と一致させるか、ここで直接定義する
    dialog_app_name = "Updater" # または "ESP32C6 Updater" など
    messagebox.showinfo(f"{dialog_app_name} について", 
                        f"{dialog_app_name}\nバージョン 1.0.0\n(C) 2025 PIL Corporation\n\n"
                        "このツールはESP32C6のファームウェアを簡単にアップデートするためのものです。\n"
                        "バイナリファイル書き込み履歴記録機能付き")

def main():
    try:
        # 多重起動チェック - 既に起動している場合は何もせずに終了
        if is_already_running():
            return

        # GUIの初期化
        root = tk.Tk()
        
        # アプリケーション名を設定
        app_name = "ESP32C6 Updater" # メニューバーやタイトルに表示する名前
        root.title(app_name) 

        # --- アプリケーション終了処理の定義 ---
        def on_closing():
            root.destroy() # ウィンドウを破棄し、mainloopを終了させる

        # ウィンドウのクローズボタン（右上など）が押されたときの処理を設定
        root.protocol("WM_DELETE_WINDOW", on_closing)

        # macOS特有の設定
        if sys.platform == 'darwin':
            # フォントサイズを調整 (お好みで)
            default_font = tk.font.nametofont("TkDefaultFont")
            default_font.configure(size=12)
            root.option_add("*Font", default_font)
            
            # ウィンドウ背景色 (お好みで)
            root.config(bg='#f0f0f0')
            
            # メニューバーの作成
            menubar = tk.Menu(root)
            
            # アプリケーションメニュー (macOSの左上の太字のメニュー)
            app_menu = tk.Menu(menubar, name='apple', tearoff=0) # 'name="apple"' が重要
            menubar.add_cascade(label=app_name, menu=app_menu) # ここで表示名を設定

            # アプリケーションメニューの項目
            app_menu.add_command(label=f"{app_name} について", command=show_about_dialog)
            app_menu.add_separator()
            app_menu.add_command(label=f"{app_name} を隠す", accelerator="Command+H", command=lambda: root.tk.call("hide", root))
            app_menu.add_command(label="ほかを隠す", accelerator="Command+Option+H", command=lambda: root.tk.call("::tk::HideOthers"))
            app_menu.add_command(label="すべてを表示", command=lambda: root.tk.call("::tk::ShowAll"))
            app_menu.add_separator()
            # "終了" コマンドは on_closing を呼び出すようにする
            app_menu.add_command(label=f"{app_name} を終了", accelerator="Command+Q", command=on_closing)

            # 作成したメニューバーをウィンドウに設定
            root.config(menu=menubar)

            # Command-Q ショートカットを明示的にバインド
            # これにより、メニューからだけでなく、直接ショートカットでも終了処理が呼ばれる
            root.bind_all("<Command-q>", lambda event: on_closing())

        # アプリケーション本体のクラスをインスタンス化
        app = ESP32C6Updater(root) 
        
        # Tkinterのメインイベントループを開始
        root.mainloop()

    except Exception as e:
        error_message = f"アプリケーション起動エラー: {e}"
        print(error_message)
        # messagebox は root が初期化されていないと表示できないことがある
        # root が存在し、かつウィンドウが存在する場合のみ表示を試みる
        if 'root' in locals() and isinstance(root, tk.Tk) and root.winfo_exists():
            messagebox.showerror("致命的なエラー", error_message)
        elif 'root' not in locals() or not isinstance(root, tk.Tk):
             # Tkinterの初期化自体に失敗した場合など
             # ここで代替のエラー表示方法 (例:標準エラー出力への詳細なスタックトレース) も検討できる
             import traceback
             traceback.print_exc()

if __name__ == "__main__":
    main()
