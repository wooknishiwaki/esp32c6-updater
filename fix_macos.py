import re

# ファイルを読み込み
with open('updater.py', 'r', encoding='utf-8') as f:
    content = f.read()

# _build_ui メソッドの最初の部分を修正
old_pattern = r'def _build_ui\(self\):\s*"""UIを構築"""\s*# メインフレーム'
new_replacement = '''def _build_ui(self):
        """UIを構築"""
        # macOS用のフォーカス修正
        if sys.platform == 'darwin':
            self.root.tk.call('tk', 'scaling', 1.0)
            self.root.lift()
            self.root.attributes('-topmost', True)
            self.root.after_idle(lambda: self.root.attributes('-topmost', False))
        
        # メインフレーム'''

content = re.sub(old_pattern, new_replacement, content)

# ファイルに書き戻し
with open('updater.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("修正完了")
