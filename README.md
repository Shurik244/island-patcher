# Island Patcher

> Disclaimer: This project is provided for educational and research purposes only. Use it at your own risk. The author(s) are not responsible for any direct or indirect damage, data loss, system failure, or account bans resulting from the use of this software.
>
> Дисклеймер: Проект создан исключительно в ознакомительных/исследовательских целях. Вы используете данное ПО на свой страх и риск. Автор не несёт ответственности за возможные сбои, потерю данных, блокировки аккаунтов или любой другой ущерб, причинённый в процессе использования.

---

[Русский](#русский) | [English](#english)

---

## Русский

Скрипт для автоматического патчинга `island.exe` (x64 PE)

Суть: находит функцию проверки лицензии и правит проверки после ее вызова, чтобы прога принимала любой введенный ключ и активировала Pro.

### Требования
Нужен Python 3.10+ и пара либ:
```bash
pip install pefile capstone
```

### Как запускать
Обычный запуск (создаст рядом `island_patched.exe`):
```bash
python patcher.py island.exe
```

Если нужно указать свое имя выходного файла:
```bash
python patcher.py island.exe -o my_patched_island.exe
```

Справка по аргументам: `python patcher.py -h`

### Как это внутри работает
1. **Поиск валидатора**: сканирует секцию `.text` на константу формата ключа `ISL1` и дефис `-`. По найденному смещению чекает таблицу исключений `.pdata`, чтобы узнать точные границы и RVA начала функции `validate_key()`.
2. **Поиск вызовов**: через дизассемблер Capstone ищет в коде все инструкции `call`, которые ведут на эту функцию.
3. **Патчинг байтов**: смотрит следующие инструкции после вызова и фиксит проверки:
   - **Тип A**: меняет `xor` на `or` (через ModR/M байт).
   - **Тип B**: в `cmp ..., 1` меняет константу с 1 на 2.
4. *(Закомментировано в коде)*: есть кусок под снятие защиты от скринкаста (`SetWindowDisplayAffinity` из user32), но в текущей версии программы он не нужен, поэтому выключен.
5. Исходный файл не трогается, результат пишется в новый exe.

### Как обновлять под новые билды если все пошло по пизде
Так как бинарник пересобирается каждое обновление, логика или сигнатуры могут немного поехать. Если патчер выдает ошибку, смотрим по чек-листу:

1. **Ошибка `NF SING` (не найдена сигнатура ключа)**:
   - Возможно, изменился префикс ключа `ISL1-`. Открываем бинарник в IDA / Ghidra  и ищем новый формат.
   - В начале `patcher.py` правим константы:
     - `MAGIC_BYTES = b"\x49\x53\x4c\x31"` (заменить на новые 4 байта)
     - `DASH_BYTE = 0x2D` (если разделитель больше не дефис)
     - `MAGIC_SEARCH_WINDOW = 12` (окно поиска дефиса после сигнатуры)
2. **Ошибка `NO CALLS`**:
   - Значит функцию заинлайнили либо вызов стал косвенным (`call rax`). Нужно глянуть в IDA переходы на функцию валидации.
3. **Предупреждение `WARN: NOT ALL PATCHES APPLIED` или `PATTERN NOT MATCH`**:
   - Компилятор поменял инструкции после вызова (например, вместо `cmp [mem], 1` появился `test eax, eax` или другие регистры).
   - Берем RVA из консоли (`RET @RVA 0x...`), находим это место в дизассемблере и смотрим первые 5–10 инструкций после `call`.
   - Дописываем новое условие в `classify_and_patch()` по аналогии с типами A и B.
4. Открываем PR? :)
---

## English
Script for automatically patching `island.exe` (x64 PE)

Overview: Finds the license verification function and modifies the checks after it is called so that the program accepts any key entered and activates the Pro version.

### Requirements
Requires Python 3.10+ and a couple of libraries:
```bash
pip install pefile capstone
```

### How to run it
Standard execution (will create `island_patched.exe` in the same directory):
```bash
python patcher.py island.exe
```
If you need to specify a custom output file name:
```bash
python patcher.py island.exe -o my_patched_island.exe
```
Help on arguments: `python patcher.py -h`

### How it works internally

1. **Validator search**: Scans the `.text` section for a constant in the `ISL1` key format and a hyphen `-`. Based on the found offset, it checks the `.pdata` exception table to determine the exact boundaries and the RVA of the `validate_key()` function’s entry point.
2. **Searching for calls**: Using the Capstone disassembler, it searches the code for all `call` instructions that lead to this function.
3. **Byte patching**: It examines the instructions following the call and fixes the checks:
   - **Type A**: Changes `xor` to `or` (using ModR/M on the byte).
   - **Type B**: In `cmp ..., 1`, changes the constant from 1 to 2.
4. *(Commented out in the code)*: There’s a section for bypassing screencast protection (`SetWindowDisplayAffinity` from user32), but it’s not needed in the current version of the program, so it’s disabled.
5. The source file remains unchanged; the result is written to a new EXE file.

### How to Update for New Builds If Things Go Pissed Off

Since the binary is recompiled with every update, the logic or signatures may get slightly messed up. If the patcher returns an error, check the checklist:
1. **`NF SING` error (key signature not found)**:
   - The `ISL1-` key prefix may have changed. Open the binary in IDA or Ghidra and look for the new format.
   - At the beginning of `patcher.py`, edit the constants:
     - `MAGIC_BYTES = b“\x49\x53\x4c\x31”` (replace with the new 4 bytes)
     - `DASH_BYTE = 0x2D` (if the separator is no longer a hyphen)
     - `MAGIC_SEARCH_WINDOW = 12` (search window for the hyphen after the signature)
2. **`NO CALLS` error**:
   - This means the function has been inlined or the call has become indirect (`call rax`). Check the jumps to the validation function in IDA.
3. **Warning `WARN: NOT ALL PATCHES APPLIED` or `PATTERN NOT MATCH`**:
   - The compiler changed the instructions after the call (for example, `cmp [mem], 1` was replaced with `test eax, eax` or other registers).
   - Get the RVA from the console (`RET @RVA 0x...`), find that location in the disassembler, and look at the first 5–10 instructions after `call`.
   - Add a new condition to `classify_and_patch()` following the same pattern as types A and B.
4. Open a PR? :)
