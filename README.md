![image](https://github.com/user-attachments/assets/456e8217-c63e-4305-843b-1b930b231c0c)
![image](https://github.com/user-attachments/assets/926793f4-cb6e-452c-b538-9391c203fca9)

Rustscan2NMap - Scan fast. Scan smart. Scan Scottish.

---

## 🛠️ Script Information

**Rustscan2NMap** is a cheeky wee Python script that blends the *blistering speed* of Rustscan with the *depth and verbosity* of NMap — saving you time and making scanning feel less like a chore and more like a dance.

With a touch of Scottish humour and a healthy dose of automation, this script:

* Uses Rustscan to rapidly identify open ports
* Passes those ports directly into NMap for full-blown enumeration
* Logs output to a specified directory (or defaults to the current one)
* Possibly saves you **up to 10^5 seconds** per scan. (Aye, possibly.)

---

## ⚙️ Dependencies

* 🦀 [Rustscan](https://github.com/RustScan/RustScan)
* 📡 [NMap](https://nmap.org/)
* 🐍 Python 3+
* 🎨 `colorama` (or *colourama*, if you're civilised)

### 💭 Suggested

* 🧠 A Brain (optional, but highly recommended)

---

## ▶️ How to Use

**Arguments:**

```
python3 rs2nm.py <target> [output_folder]
```

**Example:**

```
python3 rs2nm.py 192.168.1.10 C:\Loot
```

If no output folder is specified, it’ll default to your current working directory (`pwd`).

---

## 📁 Output

* A text or XML file with full NMap scan results
* Colour-coded terminal output for a touch of pizzazz
* Logs for later reading, reporting, or showing off

---

## 📣 Final Thoughts

This script was born out of impatience and a love for speed. It won’t make you a better hacker, but it’ll make you a faster one.

If it breaks, it’s probably your fault. If it works, you're welcome. 😉
